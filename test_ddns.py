import json
import logging
import unittest
from subprocess import CalledProcessError
from unittest.mock import ANY, MagicMock, mock_open, patch

# Import the functions and classes to be tested
import ddns

# Disable logging during tests to keep the output clean
logging.disable(logging.CRITICAL)


class TestArgParsing(unittest.TestCase):
    """Tests for the parse_args function."""

    @patch("ddns.getenv")
    def test_parse_args_normal(self, mock_getenv):
        """Test argument parsing in a standard (non-debug) environment."""
        mock_getenv.return_value = None  # Not in debug mode
        args = ["eth0", "up"]
        interface, action, is_debug, config_path = ddns.parse_args(args)
        self.assertEqual(interface, "eth0")
        self.assertEqual(action, "up")
        self.assertFalse(is_debug)
        self.assertEqual(
            config_path, "/etc/NetworkManager/dispatcher.d/ddns/config.json"
        )

    @patch("ddns.getenv")
    def test_parse_args_debug(self, mock_getenv):
        """Test argument parsing when DEBUG environment variable is set."""
        mock_getenv.return_value = "1"  # Debug mode enabled
        args = ["wlan0", "connectivity-change"]
        interface, action, is_debug, config_path = ddns.parse_args(args)
        self.assertEqual(interface, "wlan0")
        self.assertEqual(action, "connectivity-change")
        self.assertTrue(is_debug)
        self.assertEqual(config_path, "./ddns/config.json")


class TestLoggingSetup(unittest.TestCase):
    """Tests for the CustomFormatter and setup_logging function."""

    def setUp(self):
        """Save the original logging state before each test."""
        self.logger = logging.getLogger("ddns")
        self.original_level = self.logger.level
        # Make a copy of the list, not a reference
        self.original_handlers = self.logger.handlers[:].copy()

    def tearDown(self):
        """Restore the original logging state after each test."""
        self.logger.setLevel(self.original_level)
        self.logger.handlers = self.original_handlers

    def test_custom_formatter_applies_correct_colors(self):
        """Verify that the formatter applies the correct color for each log level."""
        formatter = ddns.CustomFormatter()

        # A sample record that we will modify for each level
        record = logging.LogRecord(
            name="test_logger",
            level=logging.DEBUG,  # will be changed in the loop
            pathname="/path/to/test.py",
            lineno=123,
            msg="A test message",
            args=(),
            exc_info=None,
        )

        test_cases = {
            logging.DEBUG: ddns.CustomFormatter.grey,
            logging.INFO: ddns.CustomFormatter.grey,
            logging.WARNING: ddns.CustomFormatter.yellow,
            logging.ERROR: ddns.CustomFormatter.red,
            logging.CRITICAL: ddns.CustomFormatter.bold_red,
        }

        for level, expected_color in test_cases.items():
            with self.subTest(level=logging.getLevelName(level)):
                record.levelno = level
                record.levelname = logging.getLevelName(level)

                formatted_string = formatter.format(record)

                # Check that the string starts with the color and ends with the reset code
                self.assertTrue(formatted_string.startswith(expected_color))
                self.assertTrue(formatted_string.endswith(ddns.CustomFormatter.reset))
                self.assertIn("A test message", formatted_string)
                self.assertIn("(test.py:123)", formatted_string)

    def test_setup_logging_in_different_modes(self):
        """Test setup_logging with is_debug=True."""
        root_logger = logging.getLogger("ddns")

        test_cases = [True, False]
        for is_debug in test_cases:
            with self.subTest(is_debug=is_debug):
                # Reset logger state before each subtest
                root_logger.setLevel(self.original_level)
                root_logger.handlers = self.original_handlers.copy()

                ddns.setup_logging(is_debug=is_debug, logger=root_logger)

                expected_level = logging.DEBUG if is_debug else logging.INFO
                self.assertEqual(root_logger.level, expected_level)
                self.assertEqual(
                    len(root_logger.handlers), len(self.original_handlers) + 1
                )
                handler = root_logger.handlers[-1]
                self.assertIsInstance(handler, logging.StreamHandler)
                self.assertIsInstance(handler.formatter, ddns.CustomFormatter)


class TestConfigLoading(unittest.TestCase):
    """Tests for the load_config function."""

    def test_load_config_success(self):
        """Test successful loading of a valid config file."""
        mock_config_data = json.dumps(
            {
                "email": "test@example.com",
                "api_key": "dummy_api_key",
                "zone_id": "dummy_zone_id",
                "domain_to_bind": "ddns.example.com",
                "proxy": "http://proxy.example.com:8080",
            }
        )
        m = mock_open(read_data=mock_config_data)
        with patch("builtins.open", m):
            config = ddns.load_config(
                logger=logging.getLogger("ddns"), config_path="dummy_path.json"
            )
            self.assertEqual(config.email, "test@example.com")
            self.assertEqual(config.api_key, "dummy_api_key")
            self.assertEqual(config.zone_id, "dummy_zone_id")
            self.assertEqual(config.domain_to_bind, "ddns.example.com")
            self.assertEqual(config.api_request_proxy, "http://proxy.example.com:8080")

    def test_load_config_file_not_found(self):
        """Test handling of a missing configuration file."""
        m = mock_open()
        m.side_effect = FileNotFoundError
        with patch("builtins.open", m):
            with self.assertRaises(FileNotFoundError):
                ddns.load_config(
                    config_path="non_existent_path.json",
                    logger=logging.getLogger("ddns"),
                )

    def test_load_config_json_decode_error(self):
        """Test handling of a malformed JSON configuration file."""
        invalid_json = (
            '{"email": "test@example.com", "api_key": "key"'  # Missing closing brace
        )
        m = mock_open(read_data=invalid_json)
        with patch("builtins.open", m):
            with self.assertRaises(json.JSONDecodeError):
                ddns.load_config(
                    config_path="malformed.json", logger=logging.getLogger("ddns")
                )


class TestIPAddressFetching(unittest.TestCase):
    """Tests for get_global_ip_addresses function."""

    @patch("ddns.check_output")
    @patch("ddns.which")
    def test_get_global_ip_addresses_with_iface(self, mock_which, mock_check_output):
        """Test successful fetching and filtering of IP addresses."""
        mock_which.return_value = "/usr/bin/ip"
        mock_ip_output = json.dumps(
            [
                {
                    "ifname": "eth0",
                    "addr_info": [
                        {
                            "local": "192.168.1.100",
                            "scope": "global",
                        },  # Private, should be filtered by is_global
                        {
                            "local": "fe80::1",
                            "scope": "link",
                        },  # Link-local IPv6, should be filtered
                        {"local": "2001:4:112::", "scope": "global"},  # Public IPv6
                        {
                            "local": "2001:db8::dead:beef",
                            "scope": "global",
                            "deprecated": True,
                        },  # Deprecated, should be filtered
                    ],
                }
            ]
        ).encode("utf-8")
        mock_check_output.return_value = mock_ip_output

        ips = ddns.get_global_ip_addresses("eth0", logger=logging.getLogger("ddns"))
        self.assertCountEqual(ips, ["2001:4:112::"])
        mock_check_output.assert_called_with(
            ["/usr/bin/ip", "-j", "addr", "show", "eth0"]
        )

    @patch("ddns.check_output")
    @patch("ddns.which")
    def test_get_global_ip_addresses_no_iface(self, mock_which, mock_check_output):
        """Test fetching IP addresses without specifying an interface."""
        mock_which.return_value = "/usr/bin/ip"
        mock_ip_output = json.dumps(
            [
                {
                    "ifname": "eth0",
                    "addr_info": [
                        {
                            "local": "192.168.1.100",
                            "scope": "global",
                        },  # Private, should be filtered by is_global
                        {"local": "192.31.196.1", "scope": "global"},  # Public IPv4
                        {
                            "local": "fe80::1",
                            "scope": "link",
                        },  # Link-local IPv6, should be filtered\
                        {
                            "local": "2001:db8::dead:beef",
                            "scope": "global",
                            "deprecated": True,
                        },  # Deprecated, should be filtered
                    ],
                },
                {
                    "ifname": "wlan0",
                    "addr_info": [
                        {"local": "192.168.10.100", "scope": "global"},  # Private
                        {"local": "192.31.196.10", "scope": "global"},  # Public IPv4
                        {
                            "local": "fe80::2",
                            "scope": "link",
                        },  # Link-local IPv6, should be filtered
                    ],
                },
                {
                    "ifname": "lo",
                    "addr_info": [
                        {
                            "local": "127.0.0.1",
                            "scope": "host",
                        },  # Loopback, should be filtered
                        {"local": "::1", "scope": "host"},  # Loopback, should
                    ],
                },
            ]
        )
        mock_check_output.return_value = mock_ip_output
        test_cases = [None, "", "none"]  # Test both None and empty string for iface
        for iface in test_cases:
            with self.subTest(iface=iface):
                ips = ddns.get_global_ip_addresses(
                    None, logger=logging.getLogger("ddns")
                )
                self.assertCountEqual(ips, ["192.31.196.10", "192.31.196.1"])
                mock_check_output.assert_called_with(
                    ["/usr/bin/ip", "-j", "addr", "show"]
                )

    @patch("ddns.which")
    def test_ip_command_not_found(self, mock_which):
        """Test behavior when the 'ip' command is not available."""
        mock_which.return_value = None
        with self.assertRaises(FileNotFoundError):
            ddns.get_global_ip_addresses("eth0", logger=logging.getLogger("ddns"))

    @patch("ddns.check_output")
    @patch("ddns.which")
    def test_ip_command_fails(self, mock_which, mock_check_output):
        """Test behavior when the 'ip' command fails to execute."""
        mock_which.return_value = "/usr/bin/ip"
        mock_check_output.side_effect = CalledProcessError(1, "ip")
        with self.assertRaises(RuntimeError):
            ddns.get_global_ip_addresses("eth0", logger=logging.getLogger("ddns"))


class TestApiInteraction(unittest.TestCase):
    """Tests for API request building and response parsing."""

    def setUp(self):
        self.config = ddns.Config(
            email="test@example.com",
            api_key="dummy_api_key",
            zone_id="dummy_zone_id",
            domain_to_bind="ddns.example.com",
            api_request_proxy=None,
        )

    def test_build_api_request_get(self):
        """Test building a GET request with proxy."""
        config_with_proxy = self.config
        config_with_proxy.api_request_proxy = "http://proxy.example.com:8080"
        req = ddns.build_api_request(
            config_with_proxy,
            "GET",
            subpath="12345",
            params={"name": "ddns.example.com"},
            data=None,
            logger=logging.getLogger("ddns"),
        )
        self.assertEqual(req.method, "GET")
        self.assertTrue(
            req.full_url.startswith(
                "https://api.cloudflare.com/client/v4/zones/dummy_zone_id/dns_records/12345?"
            )
        )
        self.assertEqual(req.get_header("X-auth-email"), "test@example.com")
        self.assertEqual(req.get_header("Authorization"), "Bearer dummy_api_key")

    def test_build_api_request_post(self):
        """Test building a POST request with data."""
        data = {"type": "A", "name": "test"}
        req = ddns.build_api_request(
            self.config,
            "POST",
            subpath=None,
            params=None,
            data=data,
            logger=logging.getLogger("ddns"),
        )
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.data, json.dumps(data).encode("utf-8"))
        self.assertEqual(req.get_header("Content-type"), "application/json")

    @patch("ddns.request")
    def test_parse_api_response_success(self, mock_request):
        """Test parsing a successful API response."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"success": true, "result": [1, 2]}'
        mock_request.urlopen.return_value.__enter__.return_value = mock_response

        response = ddns.parse_api_response(
            MagicMock(), logger=logging.getLogger("ddns")
        )
        self.assertEqual(response, {"success": True, "result": [1, 2]})

    @patch("ddns.request")
    def test_parse_api_response_http_error(self, mock_request):
        """Test handling of a non-200 HTTP status."""
        mock_response = MagicMock()
        mock_response.status = 403
        mock_response.reason = "Forbidden"
        mock_request.urlopen.return_value.__enter__.return_value = mock_response

        response = ddns.parse_api_response(
            MagicMock(), logger=logging.getLogger("ddns")
        )
        self.assertIsNone(response)

    @patch("ddns.request")
    def test_parse_api_json_error(self, mock_request):
        """Test handling of a JSON decoding error."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = (
            b'{"success": true, "result": [1, 2]'  # Malformed JSON
        )
        mock_request.urlopen.return_value.__enter__.return_value = mock_response

        response = ddns.parse_api_response(
            MagicMock(), logger=logging.getLogger("ddns")
        )
        self.assertIsNone(response)


class TestDNSRecordOperations(unittest.TestCase):
    """Tests for get_dns_records, add_dns_record, delete_dns_record functions."""

    def setUp(self):
        """Set up a common config object for all tests in this class."""
        self.config = ddns.Config(
            email="test@example.com",
            api_key="dummy_api_key",
            zone_id="dummy_zone_id",
            domain_to_bind="ddns.example.com",
            api_request_proxy=None,
        )

    @patch("ddns.parse_api_response")
    @patch("ddns.build_api_request")
    def test_get_dns_records_success_and_filter(self, mock_build_req, mock_parse_resp):
        """Test successful fetching of DNS records and ensure it filters for A/AAAA types."""
        # Mock the API response to include various record types
        mock_api_response = {
            "success": True,
            "result": [
                {
                    "id": "id1",
                    "type": "A",
                    "name": "ddns.example.com",
                    "content": "1.1.1.1",
                },
                {
                    "id": "id2",
                    "type": "AAAA",
                    "name": "ddns.example.com",
                    "content": "2001:db8::1",
                },
                {
                    "id": "id3",
                    "type": "CNAME",
                    "name": "ddns.example.com",
                    "content": "example.com",
                },
            ],
        }
        mock_parse_resp.return_value = mock_api_response

        # Call the function under test
        records = ddns.get_dns_records(self.config, logger=logging.getLogger("ddns"))

        # Assertions
        mock_build_req.assert_called_once_with(
            self.config,
            method="GET",
            logger=logging.getLogger("ddns"),
            params="name=ddns.example.com",
        )
        mock_parse_resp.assert_called_once()
        self.assertIsNotNone(records)
        self.assertEqual(len(records), 2)  # Should have filtered out the CNAME record
        record_types = {r["type"] for r in records}
        self.assertIn("A", record_types)
        self.assertIn("AAAA", record_types)
        self.assertNotIn("CNAME", record_types)

    @patch(
        "ddns.parse_api_response",
        return_value={"success": False, "errors": ["Auth error"]},
    )
    @patch("ddns.build_api_request")
    def test_get_dns_records_api_failure(self, mock_build_req, mock_parse_resp):
        """Test that get_dns_records returns None when the API call is not successful."""
        records = ddns.get_dns_records(self.config, logger=logging.getLogger("ddns"))
        self.assertIsNone(records)
        mock_build_req.assert_called_once()
        mock_parse_resp.assert_called_once()

    @patch("ddns.parse_api_response", return_value={"success": True})
    @patch("ddns.build_api_request")
    def test_add_dns_record_ipv4_success(self, mock_build_req, mock_parse_resp):
        """Test adding an IPv4 (A) record successfully."""
        ip_to_add = "192.0.2.1"
        result = ddns.add_dns_record(
            self.config, ip_to_add, logger=logging.getLogger("ddns")
        )

        self.assertTrue(result)
        mock_build_req.assert_called_once()
        # Check the arguments passed to build_api_request
        args, kwargs = mock_build_req.call_args
        self.assertEqual(kwargs["method"], second="POST")
        self.assertEqual(kwargs["data"]["type"], "A")
        self.assertEqual(kwargs["data"]["name"], self.config.domain_to_bind)
        self.assertEqual(kwargs["data"]["content"], ip_to_add)

    @patch("ddns.parse_api_response", return_value={"success": True})
    @patch("ddns.build_api_request")
    def test_add_dns_record_ipv6_success(self, mock_build_req, mock_parse_resp):
        """Test adding an IPv6 (AAAA) record successfully."""
        ip_to_add = "2001:db8:abcd:0012::1"
        result = ddns.add_dns_record(
            self.config, ip_to_add, logger=logging.getLogger("ddns")
        )

        self.assertTrue(result)
        mock_build_req.assert_called_once()
        args, kwargs = mock_build_req.call_args
        self.assertEqual(kwargs["data"]["type"], "AAAA")
        self.assertEqual(kwargs["data"]["content"], ip_to_add)

    @patch("ddns.parse_api_response", return_value={"success": False})
    @patch("ddns.build_api_request")
    def test_add_dns_record_failure(self, mock_build_req, mock_parse_resp):
        """Test the failure case for adding a DNS record."""
        result = ddns.add_dns_record(
            self.config, "1.2.3.4", logger=logging.getLogger("ddns")
        )
        self.assertFalse(result)

    @patch(
        "ddns.parse_api_response",
        return_value={"success": True, "result": {"id": "record_to_delete"}},
    )
    @patch("ddns.build_api_request")
    def test_delete_dns_record_success(self, mock_build_req, mock_parse_resp):
        """Test deleting a DNS record successfully."""
        record_id = "record_to_delete"
        result = ddns.delete_dns_record(
            self.config, record_id, logger=logging.getLogger("ddns")
        )

        self.assertTrue(result)
        mock_build_req.assert_called_once_with(
            self.config,
            method="DELETE",
            subpath=record_id,
            params=None,
            logger=logging.getLogger("ddns"),
        )
        mock_parse_resp.assert_called_once()

    @patch("ddns.parse_api_response", return_value=None)
    @patch("ddns.build_api_request")
    def test_delete_dns_record_failure(self, mock_build_req, mock_parse_resp):
        """Test the failure case for deleting a DNS record."""
        result = ddns.delete_dns_record(
            self.config,
            "non_existent_id",
            logger=logging.getLogger("ddns"),
        )
        self.assertFalse(result)


class TestDnsLogic(unittest.TestCase):
    """Tests for the core DNS update logic."""

    def setUp(self):
        self.all_dns_records = [
            {
                "id": "id_ipv4_old",
                "type": "A",
                "name": "ddns.example.com",
                "content": "1.1.1.1",
            },
            {
                "id": "id_ipv6_current",
                "type": "AAAA",
                "name": "ddns.example.com",
                "content": "2001:4:112::",
            },
        ]

    def test_determine_dns_actions_no_change(self):
        """Test when desired IPs match current DNS records."""
        desired_ips = {"1.1.1.1", "2001:4:112::"}
        ips_to_add, ids_to_remove = ddns.determine_dns_actions(
            self.all_dns_records, desired_ips
        )
        self.assertEqual(ips_to_add, set())
        self.assertEqual(ids_to_remove, set())

    def test_determine_dns_actions_add_only(self):
        """Test when only new IPs need to be added."""
        desired_ips = {"1.1.1.1", "2001:4:112::", "2.2.2.2"}
        ips_to_add, ids_to_remove = ddns.determine_dns_actions(
            self.all_dns_records, desired_ips
        )
        self.assertEqual(ips_to_add, {"2.2.2.2"})
        self.assertEqual(ids_to_remove, set())

    def test_determine_dns_actions_remove_only(self):
        """Test when only old DNS records need to be removed."""
        desired_ips = {"2001:4:112::"}
        ips_to_add, ids_to_remove = ddns.determine_dns_actions(
            self.all_dns_records, desired_ips
        )
        self.assertEqual(ips_to_add, set())
        self.assertEqual(ids_to_remove, {"id_ipv4_old"})

    def test_determine_dns_actions_add_and_remove(self):
        """Test when some records must be added and others removed."""
        desired_ips = {"2.2.2.2"}
        ips_to_add, ids_to_remove = ddns.determine_dns_actions(
            self.all_dns_records, desired_ips
        )
        self.assertEqual(ips_to_add, {"2.2.2.2"})
        self.assertEqual(ids_to_remove, {"id_ipv4_old", "id_ipv6_current"})

    @patch("ddns.ProcessPoolExecutor")
    def test_execute_dns_changes(self, mock_executor):
        """Test the execution of DNS additions and deletions."""
        # Mock the executor to run tasks sequentially for easier testing
        mock_pool = MagicMock()
        mock_pool.map.side_effect = lambda func, iterable: list(map(func, iterable))
        mock_executor.return_value.__enter__.return_value = mock_pool

        mock_add = MagicMock()
        mock_delete = MagicMock()

        ips_to_add = {"1.2.3.4", "2001:db8::2"}
        ids_to_remove = ["id_old_1", "id_old_2"]

        ddns.execute_dns_changes(
            ips_to_add,
            ids_to_remove,
            mock_add,
            mock_delete,
            logger=logging.getLogger("ddns"),
        )

        self.assertEqual(mock_add.call_count, 2)
        mock_add.assert_any_call("1.2.3.4")
        mock_add.assert_any_call("2001:db8::2")

        self.assertEqual(mock_delete.call_count, 2)
        mock_delete.assert_any_call("id_old_1")
        mock_delete.assert_any_call("id_old_2")

    @patch("ddns.ProcessPoolExecutor")
    def test_execute_dns_changes_no_op(self, mock_executor):
        """Test that no functions are called when there are no changes."""
        mock_add = MagicMock()
        mock_delete = MagicMock()
        ddns.execute_dns_changes(
            set(), set(), mock_add, mock_delete, logger=logging.getLogger("ddns")
        )
        mock_add.assert_not_called()
        mock_delete.assert_not_called()
        mock_executor.assert_not_called()


class TestMainFunction(unittest.TestCase):
    """Integration-style tests for the main function's control flow."""

    @patch("ddns.parse_args", return_value=("eth0", "up", False, "dummy_path"))
    @patch("ddns.setup_logging")
    @patch("ddns.load_config")
    @patch("ddns.get_global_ip_addresses")
    @patch("ddns.get_dns_records")
    @patch("ddns.determine_dns_actions")
    @patch("ddns.execute_dns_changes")
    def test_main_successful_run(
        self,
        mock_execute,
        mock_determine,
        mock_get_records,
        mock_get_ips,
        mock_load,
        mock_setup,
        mock_parse,
    ):
        """Test the main function's successful execution path."""
        # Setup mocks
        mock_get_ips.return_value = {"1.2.3.4"}
        mock_get_records.return_value = [{"content": "1.1.1.1"}]
        mock_determine.return_value = ({"1.2.3.4"}, {"record_id_to_delete"})

        # Run main
        exit_code = ddns.main()

        # Assertions
        self.assertEqual(exit_code, 0)
        mock_parse.assert_called_once()
        mock_setup.assert_called_once_with(False, logging.getLogger("ddns"))
        mock_load.assert_called_once_with(logging.getLogger("ddns"), "dummy_path")
        mock_get_ips.assert_called_once_with("eth0", logging.getLogger("ddns"))
        mock_get_records.assert_called_once()
        mock_determine.assert_called_once_with([{"content": "1.1.1.1"}], {"1.2.3.4"})
        mock_execute.assert_called_once_with(
            {"1.2.3.4"}, {"record_id_to_delete"}, ANY, ANY, ANY
        )

    @patch("ddns.parse_args", return_value=("eth0", "up", False, "dummy_path"))
    @patch("ddns.setup_logging")
    @patch("ddns.load_config")
    @patch("ddns.get_global_ip_addresses")
    @patch("ddns.get_dns_records")
    @patch("ddns.determine_dns_actions")
    @patch("ddns.execute_dns_changes")
    def test_main_successful_run_with_no_changes(
        self,
        mock_execute,
        mock_determine,
        mock_get_records,
        mock_get_ips,
        mock_load,
        mock_setup,
        mock_parse,
    ):
        """Test the main function when no DNS changes are needed."""
        # Setup mocks
        mock_get_ips.return_value = {}
        mock_get_records.return_value = []
        mock_determine.return_value = ()
        mock_parse.return_value = ("eth0", "up", True, "dummy_path")

        exit_code = ddns.main()

        self.assertEqual(exit_code, 0)
        mock_parse.assert_called_once()
        mock_setup.assert_called_once_with(True, logging.getLogger("ddns"))
        mock_load.assert_called_once_with(logging.getLogger("ddns"), "dummy_path")
        mock_get_ips.assert_called_once_with("eth0", logging.getLogger("ddns"))
        mock_get_records.assert_not_called()
        mock_determine.assert_not_called()
        mock_execute.assert_not_called()

    @patch("ddns.parse_args")
    @patch("ddns.setup_logging")
    def test_main_config_load_failure(self, mock_setup, mock_parse):
        """Test main function's behavior when config loading fails."""
        mock_parse.return_value = ("eth0", "up", False, "bad_path")
        # Patch load_config to raise an error
        with patch("ddns.load_config", side_effect=FileNotFoundError):
            exit_code = ddns.main()
            self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
