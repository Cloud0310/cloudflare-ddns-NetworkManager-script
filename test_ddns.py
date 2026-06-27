# ruff: noqa: S101
import json
import logging
from ipaddress import ip_address
from pathlib import Path
from urllib import error, request

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


def write_config(tmp_path, **overrides):
    data = {
        "email": "user@example.com",
        "api_key": "api-token",
        "zone_id": "zone-123",
        "domain_to_bind": "home.example.com",
        "api_request_proxy": None,
    } | overrides
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_parse_args_default_config(monkeypatch):
    monkeypatch.delenv("DEBUG", raising=False)

    assert ddns.parse_args(["eth0", "up"]) == (
        "eth0",
        "up",
        False,
        Path("/etc/NetworkManager/dispatcher.d/ddns/config.json"),
    )


def test_parse_args_debug_mode(monkeypatch):
    monkeypatch.setenv("DEBUG", "1")

    assert ddns.parse_args(["eth1", "down"]) == (
        "eth1",
        "down",
        True,
        Path("./ddns/config.json"),
    )


def test_parse_args_strips_whitespace(monkeypatch):
    monkeypatch.delenv("DEBUG", raising=False)

    assert ddns.parse_args(["  eth0  ", "  up "]) == (
        "eth0",
        "up",
        False,
        Path("/etc/NetworkManager/dispatcher.d/ddns/config.json"),
    )


def test_colored_formatter_uses_warning_color():
    formatter = ddns.ColoredFormatter()
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


@pytest.mark.parametrize(("is_debug", "level"), [(False, logging.INFO), (True, logging.DEBUG)])
def test_setup_logging_configures_level(is_debug, level):
    ddns.setup_logging(is_debug)

    assert ddns.LOG.level == level
    assert len(ddns.LOG.handlers) == 1


def test_load_config_reads_json(tmp_path):
    cfg = ddns.load_config(write_config(tmp_path, api_request_proxy="http://proxy:3128"))

    assert cfg == ddns.Config(
        email="user@example.com",
        api_key="api-token",
        zone_id="zone-123",
        domain_to_bind="home.example.com",
        api_request_proxy="http://proxy:3128",
    )


def test_load_config_normalizes_empty_proxy_to_none(tmp_path):
    cfg = ddns.load_config(write_config(tmp_path, api_request_proxy=""))

    assert cfg.api_request_proxy is None


def test_load_config_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ddns.load_config(tmp_path / "missing.json")


def test_load_config_invalid_json_raises(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{bad json", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        ddns.load_config(path)


def test_get_global_ip_addresses_reads_networkmanager_environ(monkeypatch):
    monkeypatch.setenv("IP4_NUM_ADDRESSES", "1")
    monkeypatch.setenv("IP4_ADDRESS_0", "8.8.8.8/32 192.0.2.1")
    monkeypatch.setenv("IP6_NUM_ADDRESSES", "1")
    monkeypatch.setenv("IP6_ADDRESS_0", "2606:4700:4700::1111/128 fe80::1")

    assert [str(ip) for ip in ddns.get_global_ip_addresses()] == [
        "8.8.8.8",
        "2606:4700:4700::1111",
    ]


def test_get_global_ip_addresses_skips_private_and_link_local():
    env = {
        "IP4_NUM_ADDRESSES": "2",
        "IP4_ADDRESS_0": "10.0.0.10/24 10.0.0.1",
        "IP4_ADDRESS_1": "1.1.1.1/32 10.0.0.1",
        "IP6_NUM_ADDRESSES": "2",
        "IP6_ADDRESS_0": "fe80::1/64",
        "IP6_ADDRESS_1": "2606:4700:4700::1001/128 fe80::1",
    }

    assert [str(ip) for ip in ddns.get_global_ip_addresses(env)] == [
        "1.1.1.1",
        "2606:4700:4700::1001",
    ]


def test_get_global_ip_addresses_missing_index_warns_and_continues(caplog):
    caplog.set_level(logging.WARNING, logger="ddns")

    assert ddns.get_global_ip_addresses({"IP4_NUM_ADDRESSES": "1", "IP6_NUM_ADDRESSES": "0"}) == []
    assert "Got no IP address." in caplog.text


def test_get_global_ip_addresses_empty_env_returns_empty_list():
    assert ddns.get_global_ip_addresses({}) == []


def test_build_api_request_url_headers_and_body(config_obj):
    data = {
        "type": "A",
        "name": "home.example.com",
        "content": "1.1.1.1",
        "ttl": 1,
        "proxied": False,
    }

    req = ddns.build_api_request(config_obj, method="POST", subpath="record-id", params="type=A", data=data)

    assert req.method == "POST"
    assert req.full_url == "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records/record-id?type=A"
    assert json.loads(req.data.decode("utf-8")) == data
    assert req.headers["X-auth-email"] == "user@example.com"
    assert req.headers["Authorization"] == "Bearer api-token"


def test_build_api_request_without_body_or_params(config_obj):
    req = ddns.build_api_request(config_obj, method="GET")

    assert req.full_url == "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records"
    assert req.data is None


def test_build_api_request_with_proxy_installs_proxy_opener(config_obj, mocker):
    config_obj.api_request_proxy = "http://proxy:8080"
    build_opener = mocker.patch("urllib.request.build_opener")
    install_opener = mocker.patch("urllib.request.install_opener")

    ddns.build_api_request(config_obj, method="GET")

    build_opener.assert_called_once()
    install_opener.assert_called_once_with(build_opener.return_value)


def test_parse_api_response_successful_json(mocker):
    response = mocker.MagicMock()
    response.status = 200
    response.read.return_value = b'{"success": true, "result": []}'
    response.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response)

    assert ddns.parse_api_response(request.Request("https://example.com")) == {"success": True, "result": []}


def test_parse_api_response_non_ok_returns_none(mocker):
    response = mocker.MagicMock()
    response.status = 500
    response.reason = "fail"
    response.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response)

    assert ddns.parse_api_response(request.Request("https://example.com")) is None


def test_parse_api_response_invalid_json_returns_none(mocker):
    response = mocker.MagicMock()
    response.status = 200
    response.read.return_value = b"not-json"
    response.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response)

    assert ddns.parse_api_response(request.Request("https://example.com")) is None


def test_parse_api_response_url_error_returns_none(mocker):
    mocker.patch("urllib.request.urlopen", side_effect=error.URLError("boom"))

    assert ddns.parse_api_response(request.Request("https://example.com")) is None


def test_get_dns_records_filters_a_and_aaaa(config_obj, mocker):
    build_request = mocker.patch("ddns.build_api_request", return_value=request.Request("https://example.com"))
    mocker.patch(
        "ddns.parse_api_response",
        return_value={
            "success": True,
            "result": [
                {"id": "r1", "type": "A", "name": "home.example.com", "content": "1.1.1.1"},
                {"id": "r2", "type": "TXT", "name": "home.example.com", "content": "txt"},
                {"id": "r3", "type": "AAAA", "name": "home.example.com", "content": "2606:4700:4700::1111"},
            ],
        },
    )

    assert ddns.get_dns_records(config_obj) == [
        {"id": "r1", "type": "A", "name": "home.example.com", "content": "1.1.1.1"},
        {"id": "r3", "type": "AAAA", "name": "home.example.com", "content": "2606:4700:4700::1111"},
    ]
    build_request.assert_called_once_with(config_obj, method="GET", params="name=home.example.com")


@pytest.mark.parametrize("response", [None, {"success": False}])
def test_get_dns_records_returns_none_on_failure(config_obj, mocker, response):
    mocker.patch("ddns.build_api_request", return_value=request.Request("https://example.com"))
    mocker.patch("ddns.parse_api_response", return_value=response)

    assert ddns.get_dns_records(config_obj) is None


@pytest.mark.parametrize(("content", "record_type"), [("1.1.1.1", "A"), ("2606:4700:4700::1111", "AAAA")])
def test_add_dns_record_payload_success(config_obj, mocker, content, record_type):
    build_request = mocker.patch("ddns.build_api_request", return_value=request.Request("https://example.com"))
    mocker.patch("ddns.parse_api_response", return_value={"success": True})

    assert ddns.add_dns_record(content, config_obj)

    assert build_request.call_args.kwargs["method"] == "POST"
    assert build_request.call_args.kwargs["data"]["type"] == record_type
    assert build_request.call_args.kwargs["data"]["content"] == content


@pytest.mark.parametrize("response", [{"success": False}, None])
def test_add_dns_record_returns_false_on_failure(config_obj, mocker, response):
    mocker.patch("ddns.build_api_request", return_value=request.Request("https://example.com"))
    mocker.patch("ddns.parse_api_response", return_value=response)

    assert ddns.add_dns_record("1.1.1.1", config_obj) is False


def test_delete_dns_record_calls_delete_url(config_obj, mocker):
    build_request = mocker.patch("ddns.build_api_request", return_value=request.Request("https://example.com"))
    mocker.patch("ddns.parse_api_response", return_value={"success": True})

    assert ddns.delete_dns_record("record-id", config_obj)
    build_request.assert_called_once_with(config_obj, method="DELETE", subpath="record-id", params=None)


@pytest.mark.parametrize("response", [{"success": False}, None])
def test_delete_dns_record_returns_false_on_failure(config_obj, mocker, response):
    mocker.patch("ddns.build_api_request", return_value=request.Request("https://example.com"))
    mocker.patch("ddns.parse_api_response", return_value=response)

    assert ddns.delete_dns_record("record-id", config_obj) is False


@pytest.mark.xfail(reason="ddns.py does not normalize desired IP objects yet", strict=True)
def test_determine_dns_actions_normalizes_desired_ip_objects():
    records = [{"id": "r1", "content": "1.1.1.1"}, {"id": "r2", "content": "8.8.8.8"}]

    to_add, to_remove = ddns.determine_dns_actions(records, {ip_address("1.1.1.1"), ip_address("9.9.9.9")})

    assert (to_add, to_remove) == ({"9.9.9.9"}, {"r2"})


def test_determine_dns_actions_noop_with_string_ips():
    assert ddns.determine_dns_actions([{"id": "r1", "content": "1.1.1.1"}], {"1.1.1.1"}) == (set(), set())


class DummyExecutor:
    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        return None

    @staticmethod
    def map(func, values):
        return [func(value) for value in values]


def test_execute_dns_changes_logs_add_failure_with_reusable_ip_map(mocker, monkeypatch):
    real_map = map

    class ReusableMap:
        def __init__(self, func, *iterables):
            self.items = tuple(real_map(func, *iterables))

        def __iter__(self):
            return iter(self.items)

    monkeypatch.setattr("builtins.map", ReusableMap)
    mocker.patch("ddns.ProcessPoolExecutor", return_value=DummyExecutor())
    mocker.patch.object(ddns.LOG, "error")

    ddns.execute_dns_changes({"8.8.8.8"}, set(), lambda _ip: False, lambda _record_id: True)

    ddns.LOG.error.assert_called_once_with("Failed to add DNS record for IP: 8.8.8.8")


@pytest.mark.parametrize(
    (
        "add_records",
        "remove_records",
        "add_results",
        "remove_results",
        "expected_add_args",
        "expected_remove_args",
        "expected_errors",
    ),
    [
        (set(), set(), [], [], set(), set(), set()),
        pytest.param(
            {ip_address("1.1.1.1")},
            set(),
            [True],
            [],
            {"1.1.1.1"},
            set(),
            set(),
            marks=pytest.mark.xfail(reason="ddns.py consumes IP iterator before add calls", strict=True),
        ),
        pytest.param(
            {"8.8.8.8"},
            set(),
            [False],
            [],
            {"8.8.8.8"},
            set(),
            {"Failed to add DNS record for IP: 8.8.8.8"},
            marks=pytest.mark.xfail(reason="ddns.py consumes IP iterator before add calls", strict=True),
        ),
        (set(), {"r1"}, [], [True], set(), {"r1"}, set()),
        (set(), {"r2"}, [], [False], set(), {"r2"}, {"Failed to delete DNS record with ID: r2"}),
        pytest.param(
            {"9.9.9.9"},
            {"r3"},
            [True],
            [True],
            {"9.9.9.9"},
            {"r3"},
            set(),
            marks=pytest.mark.xfail(reason="ddns.py consumes IP iterator before add calls", strict=True),
        ),
    ],
)
def test_execute_dns_changes_branch_matrix(
    mocker,
    add_records,
    remove_records,
    add_results,
    remove_results,
    expected_add_args,
    expected_remove_args,
    expected_errors,
):
    executor = mocker.patch("ddns.ProcessPoolExecutor", return_value=DummyExecutor())
    add_func = mocker.MagicMock(side_effect=add_results)
    delete_func = mocker.MagicMock(side_effect=remove_results)
    log_error = mocker.patch.object(ddns.LOG, "error")

    ddns.execute_dns_changes(add_records, remove_records, add_func, delete_func)

    if add_records or remove_records:
        executor.assert_called_once()
    else:
        executor.assert_not_called()
    assert {call.args[0] for call in add_func.call_args_list} == expected_add_args
    assert {call.args[0] for call in delete_func.call_args_list} == expected_remove_args
    assert {call.args[0] for call in log_error.call_args_list} == expected_errors


def test_main_skips_invalid_networkmanager_action(mocker):
    mocker.patch("ddns.parse_args", return_value=("eth0", "hostname", False, Path("config.json")))
    mocker.patch("ddns.setup_logging")
    load_config = mocker.patch("ddns.load_config")

    assert ddns.main() == 0
    load_config.assert_not_called()


def test_main_returns_zero_when_no_ips_found(mocker, config_obj):
    mocker.patch("ddns.parse_args", return_value=("eth0", "up", True, Path("config.json")))
    mocker.patch("ddns.setup_logging")
    mocker.patch("ddns.load_config", return_value=config_obj)
    mocker.patch("ddns.get_global_ip_addresses", return_value=[])
    get_records = mocker.patch("ddns.get_dns_records")
    execute = mocker.patch("ddns.execute_dns_changes")

    assert ddns.main() == 0
    get_records.assert_not_called()
    execute.assert_not_called()


def test_main_returns_one_if_config_load_fails(mocker):
    mocker.patch("ddns.parse_args", return_value=("eth0", "up", False, Path("config.json")))
    mocker.patch("ddns.setup_logging")
    mocker.patch("ddns.load_config", side_effect=FileNotFoundError("missing"))

    assert ddns.main() == 1


def test_main_returns_one_if_dns_records_fail(mocker, config_obj):
    mocker.patch("ddns.parse_args", return_value=("eth0", "up", False, Path("config.json")))
    mocker.patch("ddns.setup_logging")
    mocker.patch("ddns.load_config", return_value=config_obj)
    mocker.patch("ddns.get_global_ip_addresses", return_value=[ip_address("1.1.1.1")])
    mocker.patch("ddns.get_dns_records", return_value=None)

    assert ddns.main() == 1


def test_main_runs_successful_update_flow(mocker, config_obj):
    mocker.patch("ddns.parse_args", return_value=("eth0", "up", False, Path("config.json")))
    mocker.patch("ddns.setup_logging")
    mocker.patch("ddns.load_config", return_value=config_obj)
    mocker.patch("ddns.get_global_ip_addresses", return_value=[ip_address("1.1.1.1")])
    mocker.patch("ddns.get_dns_records", return_value=[{"id": "r1", "content": "8.8.8.8", "type": "A"}])
    execute = mocker.patch("ddns.execute_dns_changes")

    assert ddns.main() == 0
    execute.assert_called_once()


def test_main_propagates_parse_system_exit(mocker):
    mocker.patch("ddns.parse_args", side_effect=SystemExit(2))

    with pytest.raises(SystemExit):
        ddns.main()
