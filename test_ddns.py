import json
import logging
from unittest.mock import mock_open

import pytest

import ddns


@pytest.fixture
def config_obj():
    return ddns.Config(
        email="user@example.com",
        api_key="api-token",
        zone_id="zone-123",
        domain_to_bind="home.example.com",
        api_request_proxy=None,
    )


def test_parse_args_default_config(monkeypatch):
    monkeypatch.delenv("DEBUG", raising=False)
    assert ddns.parse_args(["eth0", "up"]) == (
        "eth0",
        "up",
        False,
        "/etc/NetworkManager/dispatcher.d/ddns/config.json",
    )


def test_parse_args_debug_mode(monkeypatch):
    monkeypatch.setenv("DEBUG", "1")
    assert ddns.parse_args(["eth1", "down"]) == (
        "eth1",
        "down",
        True,
        "./ddns/config.json",
    )


def test_parse_args_preserves_whitespace():
    assert ddns.parse_args(["  eth0  ", "  up "]) == (
        "eth0",
        "up",
        False,
        "/etc/NetworkManager/dispatcher.d/ddns/config.json",
    )


def test_custom_formatter_uses_warning_color():
    formatter = ddns.CustomFormatter()
    record = logging.LogRecord(
        name="ddns",
        level=logging.WARNING,
        pathname="ddns.py",
        lineno=11,
        msg="warn",
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    assert "\x1b[33;20m" in formatted
    assert "warn" in formatted


def test_setup_logging_configures_level():
    ddns.setup_logging(False)
    assert ddns.LOG.level == logging.INFO
    assert len(ddns.LOG.handlers) == 1


def test_setup_logging_configures_debug_level():
    ddns.setup_logging(True)
    assert ddns.LOG.level == logging.DEBUG


def test_load_config_reads_json(mocker):
    data = {
        "email": "user@example.com",
        "api_key": "api-token",
        "zone_id": "zone-123",
        "domain_to_bind": "home.example.com",
        "api_request_proxy": "http://proxy:3128",
    }
    mocker.patch(
        "builtins.open",
        mock_open(read_data=json.dumps(data)),
    )

    cfg = ddns.load_config("config.json")

    assert cfg == ddns.Config(
        email="user@example.com",
        api_key="api-token",
        zone_id="zone-123",
        domain_to_bind="home.example.com",
        api_request_proxy="http://proxy:3128",
    )


def test_load_config_normalizes_empty_proxy_to_none(mocker):
    data = {
        "email": "user@example.com",
        "api_key": "api-token",
        "zone_id": "zone-123",
        "domain_to_bind": "home.example.com",
        "api_request_proxy": "",
    }
    mocker.patch("builtins.open", mock_open(read_data=json.dumps(data)))
    cfg = ddns.load_config("config.json")
    assert cfg.api_request_proxy is None


def test_load_config_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        ddns.load_config("/does/not/exist.json")


def test_load_config_invalid_json_raises(mocker):
    mocker.patch("builtins.open", mock_open(read_data="{bad json"))
    with pytest.raises(json.JSONDecodeError):
        ddns.load_config("config.json")


def test_get_global_ip_addresses_builds_ip_command(mocker):
    mocker.patch("ddns.which", return_value="/usr/bin/ip")
    payload = [
        {
            "ifname": "eth0",
            "addr_info": [
                {
                    "local": "8.8.8.8",
                    "deprecated": False,
                    "scope": "global",
                },
                {"local": "127.0.0.1", "deprecated": False, "scope": "host"},
            ],
        },
        {
            "ifname": "eth1",
            "addr_info": [
                {
                    "local": "2001:4860:4860::8888",
                    "deprecated": False,
                    "scope": "global",
                }
            ],
        },
    ]
    mocker.patch("ddns.check_output", return_value=json.dumps(payload).encode())

    ips = ddns.get_global_ip_addresses("eth0")

    assert ips == ["8.8.8.8", "2001:4860:4860::8888"]
    ddns.which.assert_called_once_with("ip")
    ddns.check_output.assert_called_once_with(
        ["/usr/bin/ip", "-j", "addr", "show", "eth0"]
    )


def test_get_global_ip_addresses_all_interfaces_when_none(mocker):
    mocker.patch("ddns.which", return_value="/usr/bin/ip")
    mocker.patch("ddns.check_output", return_value=b"[]")

    ips = ddns.get_global_ip_addresses("none")

    assert ips == []
    ddns.check_output.assert_called_once_with(["/usr/bin/ip", "-j", "addr", "show"])


def test_get_global_ip_addresses_raises_when_ip_missing(mocker):
    mocker.patch("ddns.which", return_value=None)
    with pytest.raises(FileNotFoundError):
        ddns.get_global_ip_addresses("eth0")


def test_get_global_ip_addresses_raises_on_bad_ip_output(mocker):
    mocker.patch("ddns.which", return_value="/usr/bin/ip")
    mocker.patch("ddns.check_output", return_value=b"not-json")
    with pytest.raises(json.JSONDecodeError):
        ddns.get_global_ip_addresses("eth0")


def test_get_global_ip_addresses_wraps_calling_error(mocker):
    from subprocess import CalledProcessError

    mocker.patch("ddns.which", return_value="/usr/bin/ip")
    mocker.patch(
        "ddns.check_output",
        side_effect=CalledProcessError(1, "ip", output=b"err"),
    )

    with pytest.raises(RuntimeError):
        ddns.get_global_ip_addresses("eth0")


def test_build_api_request_without_proxy(config_obj):
    req = ddns.build_api_request(config_obj, method="GET")

    assert req.method == "GET"
    assert (
        req.full_url
        == "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records"
    )
    assert req.headers["X-auth-email"] == "user@example.com"
    assert req.headers["Authorization"] == "Bearer api-token"


def test_build_api_request_with_proxy_uses_proxy_handler(config_obj, mocker):
    config_obj.api_request_proxy = "http://proxy:8080"
    mock_build_opener = mocker.patch("ddns.request.build_opener")
    mock_install_opener = mocker.patch("ddns.request.install_opener")

    ddns.build_api_request(
        config_obj,
        method="POST",
        data={
            "type": "A",
            "name": "home.example.com",
            "content": "198.51.100.10",
            "ttl": 1,
            "proxied": False,
        },
    )

    assert mock_build_opener.call_count == 1
    assert mock_install_opener.call_count == 1


def test_parse_api_response_successful_json(mocker):
    response = mocker.MagicMock()
    response.status = 200
    response.read.return_value = b'{"success":true,"result":[]}'
    mocker.patch("ddns.request.urlopen", return_value=response)
    response.__enter__.return_value = response

    result = ddns.parse_api_response(ddns.request.Request("https://example.com"))

    assert result == {"success": True, "result": []}


def test_parse_api_response_http_error_is_none(mocker):
    response = mocker.MagicMock()
    response.status = 500
    response.reason = "fail"
    mocker.patch("ddns.request.urlopen", return_value=response)
    response.__enter__.return_value = response

    assert ddns.parse_api_response(ddns.request.Request("https://example.com")) is None


def test_parse_api_response_invalid_json_returns_none(mocker):
    response = mocker.MagicMock()
    response.status = 200
    response.read.return_value = b"not-json"
    mocker.patch("ddns.request.urlopen", return_value=response)
    response.__enter__.return_value = response

    assert ddns.parse_api_response(ddns.request.Request("https://example.com")) is None


def test_parse_api_response_urlopen_error_returns_none(mocker):
    mocker.patch("ddns.request.urlopen", side_effect=ddns.error.URLError("boom"))
    assert ddns.parse_api_response(ddns.request.Request("https://example.com")) is None


def test_get_dns_records_filters_aaaa_and_a(config_obj, mocker):
    mocker.patch(
        "ddns.build_api_request",
        return_value=ddns.request.Request("https://example.com"),
    )
    mocker.patch(
        "ddns.parse_api_response",
        return_value={
            "success": True,
            "result": [
                {
                    "id": "r1",
                    "type": "A",
                    "name": "home.example.com",
                    "content": "198.51.100.10",
                },
                {"id": "r2", "type": "TXT", "name": "x", "content": "abc"},
                {
                    "id": "r3",
                    "type": "AAAA",
                    "name": "home.example.com",
                    "content": "2001:db8::10",
                },
            ],
        },
    )

    records = ddns.get_dns_records(config_obj)

    assert records == [
        {
            "id": "r1",
            "type": "A",
            "name": "home.example.com",
            "content": "198.51.100.10",
        },
        {
            "id": "r3",
            "type": "AAAA",
            "name": "home.example.com",
            "content": "2001:db8::10",
        },
    ]


def test_get_dns_records_returns_none_on_failure(config_obj, mocker):
    mocker.patch(
        "ddns.build_api_request",
        return_value=ddns.request.Request("https://example.com"),
    )
    mocker.patch("ddns.parse_api_response", return_value=None)
    assert ddns.get_dns_records(config_obj) is None


def test_add_dns_record_adds_aaaa_record(config_obj, mocker):
    build_request = mocker.patch(
        "ddns.build_api_request",
        return_value=ddns.request.Request("https://example.com"),
    )
    mocker.patch("ddns.parse_api_response", return_value={"success": True})

    assert ddns.add_dns_record("2001:db8::10", config_obj)

    build_request.assert_called_once()
    called_kwargs = build_request.call_args.kwargs
    assert called_kwargs["method"] == "POST"


def test_add_dns_record_returns_false_on_failure(config_obj, mocker):
    mocker.patch(
        "ddns.build_api_request",
        return_value=ddns.request.Request("https://example.com"),
    )
    mocker.patch("ddns.parse_api_response", return_value={"success": False})

    assert ddns.add_dns_record("198.51.100.10", config_obj) is False


def test_delete_dns_record_calls_delete_url(config_obj, mocker):
    build_request = mocker.patch(
        "ddns.build_api_request",
        return_value=ddns.request.Request("https://example.com"),
    )
    mocker.patch("ddns.parse_api_response", return_value={"success": True})

    assert ddns.delete_dns_record("record-id", config_obj)
    build_request.assert_called_once_with(
        config_obj,
        method="DELETE",
        subpath="record-id",
        params=None,
    )


def test_delete_dns_record_returns_false_when_failed(config_obj, mocker):
    mocker.patch(
        "ddns.build_api_request",
        return_value=ddns.request.Request("https://example.com"),
    )
    mocker.patch("ddns.parse_api_response", return_value={"success": False})

    assert ddns.delete_dns_record("record-id", config_obj) is False


def test_determine_dns_actions_returns_add_and_remove_ids():
    all_records = [
        {"id": "r1", "content": "203.0.113.1"},
        {"id": "r2", "content": "198.51.100.1"},
    ]
    to_add, to_remove = ddns.determine_dns_actions(
        all_records, {"203.0.113.1", "192.0.2.1"}
    )

    assert to_add == {"192.0.2.1"}
    assert to_remove == {"r2"}


@pytest.mark.parametrize(
    "add_records, remove_records, add_results, remove_results, expected_error_messages",
    [
        (set(), set(), [], [], set()),
        ({"198.51.100.10"}, set(), [True], [], set()),
        (set(), {"r1"}, [], [True], set()),
        (
            {"198.51.100.10"},
            set(),
            [False],
            [],
            {"Failed to add DNS record for IP: 198.51.100.10"},
        ),
        (set(), {"r1"}, [], [False], {"Failed to delete DNS record with ID: r1"}),
        (
            {"198.51.100.10"},
            {"r1"},
            [False],
            [False],
            {
                "Failed to add DNS record for IP: 198.51.100.10",
                "Failed to delete DNS record with ID: r1",
            },
        ),
    ],
)
def test_execute_dns_changes_branch_matrix(
    mocker,
    add_records,
    remove_records,
    add_results,
    remove_results,
    expected_error_messages,
):
    class _DummyExecutor:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def map(self, func, values):
            return map(func, values)

    mocker.patch("ddns.ProcessPoolExecutor", return_value=_DummyExecutor())
    add_func = mocker.MagicMock(side_effect=add_results)
    delete_func = mocker.MagicMock(side_effect=remove_results)
    log_error = mocker.patch.object(ddns.LOG, "error")

    ddns.execute_dns_changes(add_records, remove_records, add_func, delete_func)

    assert {c.args[0] for c in add_func.call_args_list} == add_records
    assert {c.args[0] for c in delete_func.call_args_list} == remove_records

    assert {
        call.args[0] for call in log_error.call_args_list
    } == expected_error_messages


def test_main_runs_successful_flow_with_changes(mocker):
    cfg = ddns.Config(
        email="user@example.com",
        api_key="api-token",
        zone_id="zone-123",
        domain_to_bind="home.example.com",
        api_request_proxy=None,
    )
    mocker.patch("ddns.parse_args", return_value=("eth0", "up", False, "config.json"))
    mocker.patch("ddns.setup_logging")
    mocker.patch("ddns.sleep")
    mocker.patch("ddns.load_config", return_value=cfg)
    mocker.patch("ddns.get_global_ip_addresses", return_value=["198.51.100.10"])
    mocker.patch(
        "ddns.get_dns_records",
        return_value=[
            {"id": "r1", "content": "198.51.100.10", "type": "A"},
        ],
    )
    mocker.patch("ddns.determine_dns_actions", return_value=({"2001:db8::10"}, set()))
    execute = mocker.patch("ddns.execute_dns_changes")

    assert ddns.main() == 0
    execute.assert_called_once()


def test_main_returns_zero_when_no_ips_found(mocker):
    cfg = ddns.Config(
        email="user@example.com",
        api_key="api-token",
        zone_id="zone-123",
        domain_to_bind="home.example.com",
        api_request_proxy=None,
    )
    mocker.patch("ddns.parse_args", return_value=("eth0", "up", True, "config.json"))
    mocker.patch("ddns.setup_logging")
    mocker.patch("ddns.load_config", return_value=cfg)
    mocker.patch("ddns.get_global_ip_addresses", return_value=[])
    execute = mocker.patch("ddns.execute_dns_changes")

    assert ddns.main() == 0
    execute.assert_not_called()


def test_main_returns_one_if_config_is_missing(mocker):
    mocker.patch("ddns.parse_args", return_value=("eth0", "up", False, "config.json"))
    mocker.patch("ddns.setup_logging")
    mocker.patch("ddns.load_config", side_effect=FileNotFoundError("missing"))

    assert ddns.main() == 1


def test_main_returns_one_if_dns_records_fail(mocker):
    cfg = ddns.Config(
        email="user@example.com",
        api_key="api-token",
        zone_id="zone-123",
        domain_to_bind="home.example.com",
        api_request_proxy=None,
    )
    mocker.patch("ddns.parse_args", return_value=("eth0", "up", False, "config.json"))
    mocker.patch("ddns.setup_logging")
    mocker.patch("ddns.load_config", return_value=cfg)
    mocker.patch("ddns.get_global_ip_addresses", return_value=["198.51.100.10"])
    mocker.patch("ddns.get_dns_records", return_value=None)

    assert ddns.main() == 1


def test_main_propagates_parse_errors(monkeypatch):
    def explode():
        raise SystemExit(2)

    monkeypatch.setattr(ddns, "parse_args", explode)

    with pytest.raises(SystemExit):
        ddns.main()
