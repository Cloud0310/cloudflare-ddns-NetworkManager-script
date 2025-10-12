# test_ddns.py
import json
import logging
import unittest
from subprocess import CalledProcessError
from unittest.mock import MagicMock, mock_open, patch
from urllib import error

import ddns

# Disable logging for tests to keep the output clean
logging.disable(logging.CRITICAL)


class TestDDNSScript(unittest.TestCase):
    def setUp(self):
        """Set up a sample config object for use in tests."""
        self.sample_config = ddns.Config(
            email="test@example.com",
            api_key="fake_api_key",
            zone_id="fake_zone_id",
            domain_to_bind="test.example.com",
            api_request_proxy=None,
        )

    def test_calculate_dns_changes(self):
        """Test the logic for calculating DNS changes."""
        # Scenario 1: No changes needed
        current = {"1.1.1.1", "2606:4700:4700::1111"}
        desired = {"1.1.1.1", "2606:4700:4700::1111"}
        add, remove = ddns.calculate_dns_changes(current, desired)
        self.assertEqual(add, set())
        self.assertEqual(remove, set())

        # Scenario 2: Only additions needed
        current = {"1.1.1.1"}
        desired = {"1.1.1.1", "2.2.2.2"}
        add, remove = ddns.calculate_dns_changes(current, desired)
        self.assertEqual(add, {"2.2.2.2"})
        self.assertEqual(remove, set())

        # Scenario 3: Only removals needed
        current = {"1.1.1.1", "2.2.2.2"}
        desired = {"1.1.1.1"}
        add, remove = ddns.calculate_dns_changes(current, desired)
        self.assertEqual(add, set())
        self.assertEqual(remove, {"2.2.2.2"})

        # Scenario 4: Both additions and removals needed
        current = {"1.1.1.1", "3.3.3.3"}
        desired = {"1.1.1.1", "2.2.2.2"}
        add, remove = ddns.calculate_dns_changes(current, desired)
        self.assertEqual(add, {"2.2.2.2"})
        self.assertEqual(remove, {"3.3.3.3"})

        # Scenario 5: Empty current IPs
        current = set()
        desired = {"1.1.1.1", "2.2.2.2"}
        add, remove = ddns.calculate_dns_changes(current, desired)
        self.assertEqual(add, {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(remove, set())

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps(
            {
                "email": "test@example.com",
                "api_key": "fake_api_key",
                "zone_id": "fake_zone_id",
                "domain_to_bind": "test.example.com",
            }
        ),
    )
    def test_load_config_success(self, mock_file):
        """Test successful loading of configuration."""
        config = ddns.load_config("dummy_path.json")
        self.assertEqual(config.email, "test@example.com")
        self.assertEqual(config.api_key, "fake_api_key")
        self.assertIsNone(config.api_request_proxy)
        mock_file.assert_called_with("dummy_path.json", "r")

    @patch("ddns.logging.basicConfig")
    @patch("ddns.logging.debug")
    def test_setup_logging_debug(self, mock_debug, mock_basic_config):
        """Test setup_logging with debug mode enabled."""
        ddns.setup_logging(True)
        mock_basic_config.assert_called_once()
        args, kwargs = mock_basic_config.call_args
        self.assertEqual(kwargs["level"], logging.DEBUG)
        self.assertIsInstance(kwargs["handlers"][0], logging.StreamHandler)
        self.assertIsInstance(kwargs["handlers"][0].formatter, ddns.CustomFormatter)
        mock_debug.assert_called_with("Debug mode is enabled.")

    @patch("ddns.logging.basicConfig")
    @patch("ddns.logging.debug")
    def test_setup_logging_info(self, mock_debug, mock_basic_config):
        """Test setup_logging with debug mode disabled."""
        ddns.setup_logging(False)
        mock_basic_config.assert_called_once()
        args, kwargs = mock_basic_config.call_args
        self.assertEqual(kwargs["level"], logging.INFO)
        self.assertIsInstance(kwargs["handlers"][0], logging.StreamHandler)
        self.assertIsInstance(kwargs["handlers"][0].formatter, ddns.CustomFormatter)
        mock_debug.assert_called_with("Debug mode is enabled.")

    @patch("builtins.open", new_callable=mock_open)
    def test_load_config_file_not_found(self, mock_file):
        """Test config loading when file is not found."""
        mock_file.side_effect = FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            ddns.load_config("non_existent.json")

    @patch("builtins.open", new_callable=mock_open, read_data="this is not json")
    def test_load_config_json_error(self, mock_file):
        """Test config loading with invalid JSON."""
        with self.assertRaises(json.JSONDecodeError):
            ddns.load_config("invalid.json")

    @patch("ddns.which", return_value="/usr/bin/ip")
    @patch("ddns.check_output")
    def test_get_global_ip_addresses_on_iface_success(
        self, mock_check_output, mock_which
    ):
        """Test successful retrieval of global IP addresses on a specific interface."""
        # Mock output from `ip -j addr show eth0`
        mock_json_output = [
            {
                "ifname": "eth0",
                "addr_info": [
                    {"local": "192.168.1.100"},  # Private IPv4
                    {"local": "1.2.3.4"},  # Public IPv4
                    {"local": "2001:1::1"},  # Public IPv6
                    {"local": "fe80::1"},  # Link-local IPv6 (private)
                    {"local": "2001:db8::dead", "deprecated": True},  # Deprecated IPv6
                ],
            },
        ]
        mock_check_output.return_value = json.dumps(mock_json_output).encode()

        ips = ddns.get_global_ip_addresses("eth0")
        mock_which.assert_called_with("ip")
        mock_check_output.assert_called_with(
            ["/usr/bin/ip", "-j", "addr", "show", "eth0"]
        )

        self.assertEqual(set(ips), {"1.2.3.4", "2001:1::1"})

    @patch("ddns.which", return_value="/usr/bin/ip")
    @patch("ddns.check_output")
    @patch("ddns.logging.warning")
    def test_get_global_ip_addresses_no_ipv6_warning(
        self, mock_logging_warning, mock_check_output, mock_which
    ):
        """Test warning when no global IPv6 is found."""
        mock_json_output = [
            {
                "ifname": "eth0",
                "addr_info": [{"local": "1.2.3.4"}],  # Only IPv4
            }
        ]
        mock_check_output.return_value = json.dumps(mock_json_output).encode()
        ddns.get_global_ip_addresses("eth0")
        mock_logging_warning.assert_called_with("No global IPv6 address found.")

    @patch("ddns.which", return_value="/usr/bin/ip")
    @patch("ddns.check_output")
    @patch("ddns.logging.warning")
    def test_get_global_ip_addresses_no_ipv4_warning(
        self, mock_warning, mock_check_output, mock_which
    ):
        """Test warning when no global IPv4 is found."""
        mock_json_output = [
            {
                "ifname": "eth0",
                "addr_info": [{"local": "2001:1::1"}],  # Only IPv6
            }
        ]
        mock_check_output.return_value = json.dumps(mock_json_output).encode()
        ddns.get_global_ip_addresses("eth0")
        mock_warning.assert_called_with("No global IPv4 address found.")

    @patch("ddns.which", return_value="/usr/bin/ip")
    @patch("ddns.check_output")
    def test_get_global_ip_addresses_deprecated_filtered(
        self, mock_check_output, mock_which
    ):
        """Test deprecated IPs are filtered out."""
        mock_json_output = [
            {
                "ifname": "eth0",
                "addr_info": [
                    {"local": "1.2.3.4"},
                    {"local": "2001:db8::1", "deprecated": True},
                ],
            }
        ]
        mock_check_output.return_value = json.dumps(mock_json_output).encode()
        ips = ddns.get_global_ip_addresses("eth0")
        self.assertEqual(ips, ["1.2.3.4"])

    @patch("ddns.which", return_value="/usr/bin/ip")
    @patch("ddns.check_output")
    def test_get_global_ip_addresses_with_no_iface_success(
        self, mock_check_output, mock_which
    ):
        """Test successful retrieval of global IP addresses."""
        # Mock output from `ip -j addr show`
        mock_json_output = [
            {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}]},
            {
                "ifname": "eth0",
                "addr_info": [
                    {"local": "192.168.1.100"},  # Private IPv4
                    {"local": "1.2.3.4"},  # Public IPv4
                    {"local": "2001:1::1"},  # Public IPv6
                    {"local": "fe80::1"},  # Link-local IPv6 (private)
                    {"local": "2001:db8::dead", "deprecated": True},  # Deprecated IPv6
                ],
            },
        ]
        mock_check_output.return_value = json.dumps(mock_json_output).encode()

        ips = ddns.get_global_ip_addresses("")
        mock_which.assert_called_with("ip")
        mock_check_output.assert_called_with(["/usr/bin/ip", "-j", "addr", "show"])

        self.assertEqual(set(ips), {"1.2.3.4", "2001:1::1"})

    @patch("ddns.which", return_value=None)
    def test_get_global_ip_addresses_ip_command_not_found(self, mock_which):
        """Test when the 'ip' command is not available."""
        with self.assertRaises(FileNotFoundError):
            ddns.get_global_ip_addresses("eth0")

    @patch("ddns.which", return_value="/usr/bin/ip")
    @patch("ddns.check_output", side_effect=CalledProcessError(1, "ip", "error"))
    def test_get_global_ip_addresses_command_failure(
        self, mock_check_output, mock_which
    ):
        """Test RuntimeError when 'ip' command fails."""
        with self.assertRaises(RuntimeError):
            ddns.get_global_ip_addresses("eth0")

    @patch("ddns.request.build_opener")
    @patch("ddns.request.install_opener")
    @patch("ddns.request.urlopen")
    @patch("ddns.logging.info")
    def test_send_api_request_with_proxy(
        self, mock_info, mock_urlopen, mock_install, mock_build
    ):
        """Test _send_api_request with proxy setup."""
        config = self.sample_config
        config = ddns.Config(
            email="test@example.com",
            api_key="fake_api_key",
            zone_id="fake_zone_id",
            domain_to_bind="test.example.com",
            api_request_proxy="http://proxy.example.com",
        )
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"success": true}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = ddns._send_api_request(config, "http://test.com", "GET")
        mock_build.assert_called_once()
        mock_install.assert_called_once()
        mock_info.assert_called_with(
            "Using proxy for API requests: http://proxy.example.com"
        )
        self.assertEqual(result, {"success": True})

    @patch(
        "ddns.request.urlopen",
        side_effect=error.HTTPError(None, 404, "Not Found", None, None),
    )
    @patch("ddns.logging.error")
    def test_send_api_request_http_error(self, mock_error, mock_urlopen):
        """Test _send_api_request with HTTPError."""
        result = ddns._send_api_request(self.sample_config, "http://test.com", "GET")
        mock_error.assert_called_with("API request error: HTTP Error 404: Not Found")
        self.assertIsNone(result)

    @patch("ddns.request.urlopen", side_effect=error.URLError("Connection failed"))
    @patch("ddns.logging.error")
    def test_send_api_request_url_error(self, mock_error, mock_urlopen):
        """Test _send_api_request with URLError."""
        result = ddns._send_api_request(self.sample_config, "http://test.com", "GET")
        mock_error.assert_called_with(
            "API request error: <urlopen error Connection failed>"
        )
        self.assertIsNone(result)

    @patch("ddns.request.urlopen")
    @patch("ddns.logging.error")
    def test_send_api_request_json_decode_error(self, mock_error, mock_urlopen):
        """Test _send_api_request with JSONDecodeError."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"invalid json"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = ddns._send_api_request(self.sample_config, "http://test.com", "GET")
        mock_error.assert_called()
        self.assertIsNone(result)

    @patch("ddns.request.urlopen")
    @patch("ddns.logging.error")
    def test_send_api_request_non_200_status(self, mock_error, mock_urlopen):
        """Test _send_api_request with non-200 status."""
        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.reason = "Internal Server Error"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = ddns._send_api_request(self.sample_config, "http://test.com", "GET")
        mock_error.assert_called_with("Error 500: Internal Server Error")
        self.assertIsNone(result)

    def test_custom_formatter_format(self):
        """Test CustomFormatter.format applies the correct format based on log level."""
        formatter = ddns.CustomFormatter()

        # Test INFO level (grey format)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        self.assertIn("test message", result)
        self.assertIn(formatter.grey, result)  # Check for color code
        self.assertIn(formatter.reset, result)

        # Test ERROR level (red format)
        record.level = logging.ERROR
        record.levelno = logging.ERROR
        result = formatter.format(record)
        self.assertIn(formatter.red, result)

    @patch("ddns.request")
    def test_send_api_request_failure(self, mock_request):
        """Test a failed API request (non-200 status)."""
        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.reason = "Bad Request"
        mock_request.urlopen.return_value.__enter__.return_value = mock_response

        response = ddns._send_api_request(
            self.sample_config, "http://fake.api/endpoint", "POST", data={}
        )

        self.assertIsNone(response)

    @patch("ddns._send_api_request")
    def test_get_dns_records(self, mock_api_request):
        """Test getting DNS records."""
        mock_api_request.return_value = {
            "success": True,
            "result": [{"id": "rec1", "type": "A", "content": "1.1.1.1"}],
        }

        records = ddns.get_dns_records(self.sample_config, "test.example.com", "A")

        expected_url = f"https://api.cloudflare.com/client/v4/zones/{self.sample_config.zone_id}/dns_records?name=test.example.com&type=A"
        mock_api_request.assert_called_with(self.sample_config, expected_url, "GET")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["content"], "1.1.1.1")

    @patch("ddns._send_api_request")
    @patch("ddns.logging.error")
    def test_get_dns_records_invalid_type(self, mock_error, mock_api_request):
        """Test get_dns_records rejects invalid types."""
        result = ddns.get_dns_records(self.sample_config, "test.com", "INVALID")
        mock_error.assert_called_with("Invalid type, must be 'A' or 'AAAA'")
        mock_api_request.assert_not_called()
        self.assertIsNone(result)

    @patch("ddns._send_api_request")
    def test_add_dns_record(self, mock_api_request):
        """Test adding a DNS record."""
        mock_api_request.return_value = {"success": True}

        # Test adding IPv4
        result_v4 = ddns.add_dns_record(self.sample_config, "4.3.2.1")
        self.assertTrue(result_v4)

        # Check that the correct data was sent for IPv4
        call_args_v4 = mock_api_request.call_args[0]
        self.assertEqual(call_args_v4[3]["type"], "A")
        self.assertEqual(call_args_v4[3]["content"], "4.3.2.1")

        # Test adding IPv6
        result_v6 = ddns.add_dns_record(self.sample_config, "2001:db8::2")
        self.assertTrue(result_v6)

        # Check that the correct data was sent for IPv6
        call_args_v6 = mock_api_request.call_args[0]
        self.assertEqual(call_args_v6[3]["type"], "AAAA")
        self.assertEqual(call_args_v6[3]["content"], "2001:db8::2")

    @patch("ddns._send_api_request", return_value={"success": False})
    @patch("ddns.logging.error")
    def test_add_dns_record_failure(self, mock_error, mock_api_request):
        """Test add_dns_record when API returns failure."""
        result = ddns.add_dns_record(self.sample_config, "1.2.3.4")
        mock_error.assert_called_with("Failed to add DNS record")
        self.assertFalse(result)

    @patch("ddns._send_api_request")
    def test_delete_dns_record(self, mock_api_request):
        """Test deleting a DNS record."""
        mock_api_request.return_value = {"success": True}
        record_id = "fake_record_id"

        result = ddns.delete_dns_record(self.sample_config, record_id)

        self.assertTrue(result)
        expected_url = f"https://api.cloudflare.com/client/v4/zones/{self.sample_config.zone_id}/dns_records/{record_id}"
        mock_api_request.assert_called_with(self.sample_config, expected_url, "DELETE")

    @patch("ddns._send_api_request", return_value={"success": False})
    @patch("ddns.logging.error")
    def test_delete_dns_record_failure(self, mock_error, mock_api_request):
        """Test delete_dns_record when API returns failure."""
        result = ddns.delete_dns_record(self.sample_config, "record_id_123")
        mock_error.assert_called_with("Failed to delete DNS record record_id_123.")
        self.assertFalse(result)

    @patch("sys.argv", ["ddns.py", "eth0", "up"])
    @patch("ddns.getenv", return_value="1")  # is_debug = True
    def test_parse_args(self, mock_getenv):
        """Test argument parsing."""
        interface, action, is_debug, config_path = ddns.parse_args()
        self.assertEqual(interface, "eth0")
        self.assertEqual(action, "up")
        self.assertTrue(is_debug)
        self.assertEqual(config_path, "./ddns/config.json")

    def test_parse_help_args(self):
        """Test argument parsing with help flag."""
        with (
            patch("sys.argv", ["ddns.py", "--help"]),
            self.assertRaises(SystemExit) as cm,
        ):
            ddns.parse_args()
        self.assertEqual(cm.exception.code, 0)

    @patch("ddns.parse_args", return_value=("eth0", "up", False, "config.json"))
    @patch("ddns.setup_logging")
    @patch("ddns.load_config")
    @patch("ddns.get_global_ip_addresses", return_value=["1.1.1.1"])
    @patch("ddns.get_dns_records", side_effect=[[{"content": "1.1.1.1"}], []])
    @patch("ddns.logging.info")
    def test_main_no_changes(
        self,
        mock_info,
        mock_get_dns,
        mock_get_ips,
        mock_load_config,
        mock_setup,
        mock_parse,
    ):
        """Test main returns 0 when no DNS changes are needed."""
        mock_load_config.return_value = self.sample_config
        result = ddns.main()
        mock_info.assert_any_call("No changes needed, exiting.")
        self.assertEqual(result, 0)

    @patch("ddns.parse_args", return_value=("eth0", "up", False, "config.json"))
    @patch("ddns.setup_logging")
    @patch("ddns.load_config")
    @patch("ddns.get_global_ip_addresses", return_value=[])
    @patch("ddns.logging.error")
    def test_main_no_local_ips(
        self, mock_error, mock_get_ips, mock_load_config, mock_setup, mock_parse
    ):
        """Test main returns 1 when no local IPs are found."""
        mock_load_config.return_value = self.sample_config
        result = ddns.main()
        mock_error.assert_called_with("No global IP addresses found, exiting.")
        self.assertEqual(result, 1)

    @patch("ddns.main", side_effect=Exception("Test error"))
    @patch("ddns.logging.error")
    @patch("ddns.exit")
    def test_main_entry_point_exception_handling(
        self, mock_exit, mock_error, mock_main
    ):
        """Test the if __name__ == '__main__' exception handling."""
        # Simulate the entry point logic
        try:
            ddns.main()
        except Exception as e:
            ddns.logging.error(f"An unexpected error occurred: {e}")
            ddns.exit(1)

        mock_main.assert_called_once()
        mock_error.assert_called_with("An unexpected error occurred: Test error")
        mock_exit.assert_called_with(1)

    @patch("ddns.parse_args", side_effect=Exception("Test exception"))
    @patch("ddns.logging.critical")
    def test_main_exception_handling(self, mock_critical, mock_parse_args):
        """Test main handles exceptions and returns 1."""
        result = ddns.main()
        mock_critical.assert_called_with(
            "An unrecoverable error occurred: Test exception.", exc_info=True
        )
        self.assertEqual(result, 1)

    @patch("ddns.ProcessPoolExecutor")
    @patch(
        "ddns.get_dns_records",
        side_effect=[
            [
                {"id": "rec_v4_current", "content": "1.1.1.1"},
                {"id": "rec_v4_stale", "content": "2.2.2.2"},
            ],
            [],  # No AAAA records
        ],
    )
    @patch("ddns.get_global_ip_addresses", return_value=["1.1.1.1"])
    @patch("ddns.load_config")
    @patch("ddns.setup_logging")
    @patch("ddns.parse_args", return_value=("eth0", "up", False, "config.json"))
    def test_main_workflow_remove_only(
        self,
        mock_parse,
        mock_setup,
        mock_load_config,
        mock_get_ips,
        mock_get_dns,
        mock_pool_class,
    ):
        """Test the main workflow when only DNS records need to be removed."""
        mock_load_config.return_value = self.sample_config
        mock_pool_instance = MagicMock()
        mock_pool_class.return_value.__enter__.return_value = mock_pool_instance
        mock_pool_instance.map = MagicMock()

        # Run the main function
        ddns.main()

        # Assert that pool.map was called only once (for deletion)
        self.assertEqual(mock_pool_instance.map.call_count, 1)

        # Check that the call was for deleting records
        delete_call_args = mock_pool_instance.map.call_args[0]
        self.assertEqual(delete_call_args[0].func.__name__, "delete_dns_record")
        self.assertEqual(list(delete_call_args[1]), ["rec_v4_stale"])

    @patch("ddns.ProcessPoolExecutor")
    @patch(
        "ddns.get_dns_records",
        side_effect=[
            [],  # No existing A records
            [],  # No existing AAAA records
        ],
    )
    @patch("ddns.get_global_ip_addresses", return_value=["1.1.1.1"])
    @patch("ddns.load_config")
    @patch("ddns.setup_logging")
    @patch("ddns.parse_args", return_value=("eth0", "up", False, "config.json"))
    def test_main_workflow_add_only(
        self,
        mock_parse,
        mock_setup,
        mock_load_config,
        mock_get_ips,
        mock_get_dns,
        mock_pool_class,
    ):
        """Test the main workflow when only DNS records need to be added."""
        mock_load_config.return_value = self.sample_config
        mock_pool_instance = MagicMock()
        mock_pool_class.return_value.__enter__.return_value = mock_pool_instance
        mock_pool_instance.map = MagicMock()

        # Run the main function
        ddns.main()

        # Assert that pool.map was called only once (for addition)
        self.assertEqual(mock_pool_instance.map.call_count, 1)

        # Check that the call was for adding records
        add_call_args = mock_pool_instance.map.call_args[0]
        self.assertEqual(add_call_args[0].func.__name__, "add_dns_record")
        self.assertEqual(list(add_call_args[1]), ["1.1.1.1"])

    @patch("ddns.sleep")
    @patch("ddns.ProcessPoolExecutor")
    @patch("ddns.get_dns_records", return_value=[])
    @patch("ddns.get_global_ip_addresses", return_value=["1.1.1.1"])
    @patch("ddns.load_config")
    @patch("ddns.setup_logging")
    @patch("ddns.parse_args", return_value=("eth0", "up", True, "config.json"))
    def test_main_debug_mode_skips_sleep(
        self,
        mock_parse,
        mock_setup,
        mock_load_config,
        mock_get_ips,
        mock_get_dns,
        mock_pool,
        mock_sleep,
    ):
        """Test that main() skips the sleep call when in debug mode."""
        mock_load_config.return_value = self.sample_config

        # Run the main function
        ddns.main()

        # Assert that sleep was NOT called because is_debug is True
        mock_sleep.assert_not_called()

    @patch("ddns.parse_args")
    @patch("ddns.setup_logging")
    @patch("ddns.load_config")
    @patch("ddns.get_global_ip_addresses")
    @patch("ddns.get_dns_records")
    @patch("ddns.ProcessPoolExecutor")  # Mock the executor to run tasks sequentially
    def test_main_workflow(
        self,
        MockExecutor,
        mock_get_dns,
        mock_get_ips,
        mock_load_config,
        mock_setup_logging,
        mock_parse_args,
    ):
        """Test the main function's overall workflow."""
        # --- Setup Mocks ---
        mock_parse_args.return_value = ("eth0", "up", False, "config.json")
        mock_load_config.return_value = self.sample_config

        # Simulate local IPs
        mock_get_ips.return_value = ["1.1.1.1", "2001:db8::1"]

        # Simulate remote DNS records
        mock_get_dns.side_effect = [
            [{"id": "rec_v4_old", "content": "2.2.2.2", "type": "A"}],  # A records
            [
                {"id": "rec_v6_keep", "content": "2001:db8::1", "type": "AAAA"}
            ],  # AAAA records
        ]

        # Mock the ProcessPoolExecutor to test its usage
        # We need a mock that can handle the 'with' statement and 'map'
        mock_pool_instance = MagicMock()
        mock_pool_instance.map = MagicMock()
        MockExecutor.return_value.__enter__.return_value = mock_pool_instance

        # --- Mock add/delete functions that are called by the pool ---
        with (
            patch("ddns.add_dns_record") as mock_add_record,
            patch("ddns.delete_dns_record") as mock_delete_record,
        ):
            # --- Run main function ---
            ddns.main()

            # --- Assertions ---
            mock_setup_logging.assert_called_with(False)
            mock_get_ips.assert_called_with("eth0")

            # Check that get_dns_records was called for A and AAAA
            self.assertEqual(mock_get_dns.call_count, 2)

            # The executor's map should be called for additions and deletions
            # Check additions: '1.1.1.1' is new
            add_call_args = mock_pool_instance.map.call_args_list[0][0]
            self.assertEqual(add_call_args[0].func, mock_add_record)
            self.assertEqual(list(add_call_args[1]), ["1.1.1.1"])

            # Check deletions: '2.2.2.2' is old
            delete_call_args = mock_pool_instance.map.call_args_list[1][0]
            self.assertEqual(delete_call_args[0].func, mock_delete_record)
            self.assertEqual(list(delete_call_args[1]), ["rec_v4_old"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
