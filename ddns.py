#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
from argparse import ArgumentParser
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_interface
from os import environ
from pathlib import Path
from sys import exit, stdout
from time import sleep
from typing import TYPE_CHECKING, override
from urllib import error, parse, request

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any, Literal

type IPAddress = IPv4Address | IPv6Address


@dataclass
class Config:
    email: str
    api_key: str
    zone_id: str
    domain_to_bind: str
    api_request_proxy: str | None


LOG = logging.getLogger("ddns")


class ColoredFormatter(logging.Formatter):
    def __init__(self):
        grey = "\x1b[38;20m"
        yellow = "\x1b[33;20m"
        red = "\x1b[31;20m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"
        _format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

        self.FORMATS = {
            logging.DEBUG: grey + _format + reset,
            logging.INFO: grey + _format + reset,
            logging.WARNING: yellow + _format + reset,
            logging.ERROR: red + _format + reset,
            logging.CRITICAL: bold_red + _format + reset,
        }

    @override
    def format(self, record: logging.LogRecord):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setup_logging(is_debug: bool) -> None:
    """Setup logging configuration.

    Args:
        is_debug (bool): If True, set logging level to DEBUG, else INFO.
    """
    log_level = logging.DEBUG if is_debug else logging.INFO
    handler = logging.StreamHandler(stdout)
    handler.setFormatter(ColoredFormatter())

    LOG.setLevel(log_level)
    # avoid duplicate handlers if setup_logging is called multiple times
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.debug("Debug mode is enabled.")


def parse_args(
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> tuple[str, str, bool, Path]:
    """Parse Command Line Args

    Args:
        args (list[str] | None, optional): Command Line args. Defaults to None.

    Returns:
        tuple[str, str, bool, Path]: A tuple containing:
            - INTERFACE (str): Network interface that triggered the script.
            - ACTION (str): NetworkManager action to trigger the script.
            - is_debug (bool): True if DEBUG environment variable is set to "1".
            - config_path (Path): Path to the configuration file.
    """
    if not env:
        env = dict(environ)

    parser = ArgumentParser(
        prog="ddns.py",
        usage="ddns.py INTERFACE ACTION",
        description="Cloudflare DDNS Updater for NetworkManager",
    )

    parser.add_argument(
        "INTERFACE",
        type=str,
        help="Network interface that triggered the script. Can be empty or 'none'.",
    )
    parser.add_argument(
        "ACTION",
        type=str,
        help="NetworkManager action to trigger the script.",
    )
    parsed = parser.parse_args(args)
    is_debug = env.get("DEBUG") == "1"
    config_path = (
        Path("/etc/NetworkManager/dispatcher.d/ddns/config.json")
        if not is_debug
        else Path("./ddns/config.json")  # use a local config file for debugging
    )
    LOG.debug(f"config path is {config_path!s}")
    return parsed.INTERFACE.strip(), parsed.ACTION.strip(), is_debug, config_path


def load_config(config_path: Path = Path("config.json")) -> Config:
    """Load configuration from a JSON file.
    Args:
        config_path (Path, optional): Path to the configuration file. Defaults to Path("config.json").
    Returns:
        Config: The loaded configuration as a Config object.
    """
    try:
        with config_path.open(encoding="utf-8") as file:
            data = json.load(file)
            config = Config(
                email=data["email"],
                api_key=data["api_key"],
                zone_id=data["zone_id"],
                domain_to_bind=data["domain_to_bind"],
                api_request_proxy=data.get("api_request_proxy") or None,
            )
            LOG.debug(f"Configuration loaded from {config_path}")
            return config
    except FileNotFoundError:
        LOG.exception(f"Configuration file {config_path} not found.")
        raise
    except json.JSONDecodeError as e:
        LOG.exception(f"Error decoding JSON from {config_path}: {e.msg}")
        raise


def get_global_ip_addresses(
    env: dict[str, str] | None = None,
) -> set[IPAddress]:
    """Get global IPv4 and IPv6 addresses from NetworkManager dispatcher env vars.

    Reads:
        IP4_NUM_ADDRESSES
        IP4_ADDRESS_N
        IP6_NUM_ADDRESSES
        IP6_ADDRESS_N

    Returns:
        set[IPAddress]: global IP addresses.
    """

    if env is None:
        env = dict(environ)

    global_ip_addresses: set[IPAddress] = set()

    for version in (4, 6):
        ip_count = f"IP{version}_NUM_ADDRESSES"
        address_var_prefix = f"IP{version}_ADDRESS"

        count = int(env.get(ip_count, "0"))

        for index in range(count):
            var_name = f"{address_var_prefix}_{index}"
            raw = env.get(var_name)

            if not raw:
                LOG.warning("Got no IP address.")
                continue

                # NetworkManager format:
                #    "address/prefix gateway"
                # e.g.:
                #   "192.0.2.10/24 192.0.2.1"
                #   "2001:db8::10/64 fe80::1"
                #
                # The first token is the local address with prefix.

            iface_addr = ip_interface(raw.split()[0])

            local_ip = iface_addr.ip

            if local_ip.is_global:
                global_ip_addresses.add(local_ip)

    # Warn if no global IPv4 or IPv6 address is found
    if not any(ip_address(ip).version == 4 for ip in global_ip_addresses):  # noqa: PLR2004
        LOG.warning("No global IPv4 address found.")
    if not any(ip_address(ip).version == 6 for ip in global_ip_addresses):  # noqa: PLR2004
        LOG.warning("No global IPv6 address found.")

    return set(global_ip_addresses)


def build_api_request(
    config: Config,
    method: Literal["GET", "POST", "DELETE"],
    subpath: str | None = None,
    params: str | None = None,
    data: dict[str, Any] | None = None,
) -> request.Request:
    """Build an API request to Cloudflare.

    Args:
        config (Config): Configuration object containing authentication details.
        method (Literal["GET", "POST", "DELETE"]): HTTP method.
        params (str | None): encoded URL parameters to append to the endpoint, optional.
        subpath (str | None): API endpoint subpath, optional.
        data (dict[str, Any] | None, optional): The request payload, optional.

    Returns:
        request.Request: a Request object ready to be sent.
    """
    headers = {
        "X-Auth-Email": config.email,
        "Authorization": "Bearer " + config.api_key,
        "Content-Type": "application/json",
    }
    body = json.dumps(data).encode("utf-8") if data else None

    if config.api_request_proxy:
        proxy_handler = request.ProxyHandler(
            {
                "http": config.api_request_proxy,
                "https": config.api_request_proxy,
            }
        )
        opener = request.build_opener(proxy_handler)
        request.install_opener(opener)
        LOG.info(f"Using proxy for API requests: {config.api_request_proxy}")

    endpoint = f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/dns_records"
    url = f"{endpoint}/{subpath}" if subpath else endpoint
    url = f"{url}?{params}" if params else url

    return request.Request(url, method=method, data=body, headers=headers)


# impure function to handle Network IO
def parse_api_response(req: request.Request) -> dict[str, Any] | None:
    """Open and parse the API response.

    Args:
        req (request.Request): A request Object

    Returns:
        dict[str, Any] | None: The response data in json format.
    """
    try:
        with request.urlopen(req, timeout=5) as response:
            if response.status == HTTPStatus.OK:
                return json.loads(response.read().decode("utf-8"))
            LOG.error(f"Error {response.status}: {response.reason}")
            return None
    except (error.HTTPError, error.URLError, json.JSONDecodeError):
        return None


def get_dns_records(config: Config) -> list[dict[str, int | bool | str]] | None:
    """Get DNS records of type "A" and "AAAA".

    Args:
        config (Config): Configuration object containing zone_id and domain_to_bind.

    Returns:
        list | None: a list of DNS records if found, None otherwise.
    """

    params = parse.urlencode({"name": config.domain_to_bind})

    req = build_api_request(
        config,
        method="GET",
        params=params,
    )

    response = parse_api_response(req)

    # filter the records to only include A and AAAA types
    if response and response.get("success"):
        filtered_records: list[dict[str, int | bool | str]] = list(
            filter(lambda r: r["type"] in {"A", "AAAA"}, response.get("result", []))
        )
        LOG.debug(f"Fetched {len(filtered_records)} DNS records for {config.domain_to_bind}")
        return filtered_records

    LOG.exception("Failed to fetch DNS records")
    return None


def add_dns_record(content: str, config: Config) -> bool:
    """Add a new DNS record with the given name and content.

    Args:
        content (str): content for the new DNS, usually an IP address.
        config (Config): Configuration object containing authentication details.

    Returns:
        bool: True if the addition was successful, False otherwise
    """
    LOG.debug(f"Adding DNS record: {config.domain_to_bind} -> {content}")

    data = {
        "type": "A" if ip_address(content).version == 4 else "AAAA",  # noqa: PLR2004
        "name": config.domain_to_bind,
        "content": content,
        "ttl": 1,  # Setting to 1 means 'automatic'
        "proxied": False,
    }

    req = build_api_request(config, method="POST", subpath=None, params=None, data=data)
    resp = parse_api_response(req)

    if resp and resp.get("success"):
        LOG.info(f"DNS record added successfully: {config.domain_to_bind} -> {content}")
        return True

    LOG.error("Failed to add DNS record")
    return False


def delete_dns_record(record_id: str, config: Config) -> bool:
    """Delete a DNS record by its ID.

    Args:
        record_id (str): the ID of the DNS record to delete
        config (Config): Configuration object containing authentication details.

    Returns:
        bool: True if the deletion was successful, False otherwise
    """
    LOG.debug(f"Deleting DNS record with ID: {record_id}")
    req = build_api_request(config, method="DELETE", subpath=record_id, params=None)
    response = parse_api_response(req)
    if response and response.get("success"):
        LOG.info(f"DNS record {record_id} deleted successfully.")
        return True
    LOG.error(f"Failed to delete DNS record {record_id}.")
    return False


def determine_dns_actions(
    all_dns_records: list[dict[str, Any]], desired_ips: set[IPAddress]
) -> tuple[set[IPAddress], set[str]]:
    """Determine which DNS records need to be added or removed.

    Args:
        all_dns_records (list[dict[str, Any]]): List of current DNS records.
        desired_ips (set[IPAddress]): Set of desired IP addresses.

    Returns:
        tuple[set[IPAddress], set[str]]: A tuple containing two sets:
            - ips_to_add (set[IPAddress]): IP addresses that need to be added as DNS records
            - record_ids_to_remove (set[str]): DNS record ids that need to be removed from DNS records
    """
    current_ips = set({ip_address(record["content"]) for record in all_dns_records})

    ips_to_add = desired_ips - current_ips
    ips_to_remove = current_ips - desired_ips
    record_ids_to_remove: set[str] = {
        record["id"] for record in all_dns_records if ip_address(record["content"]) in ips_to_remove
    }
    return ips_to_add, record_ids_to_remove


def execute_dns_changes(
    ips_to_add: set[IPAddress],
    record_ids_to_remove: set[str],
    add_record_func: Callable[[str], bool],
    delete_record_func: Callable[[str], bool],
) -> None:
    """Execute DNS changes in parallel using ProcessPoolExecutor.

    Args:
        ips_to_add (set[IPAddress]): Set of IP addresses to add as DNS records.
        record_ids_to_remove (set[str]): Set of DNS record IDs to remove.
        add_record_func (Callable[[str], bool]): Function to add a DNS record.
        delete_record_func (Callable[[str], bool]): Function to delete a DNS record.
    """
    if not (ips_to_add or record_ids_to_remove):
        LOG.info("No DNS changes needed.")
        return
    # IPv4Address and IPv6Address cannot be serialized into json, so cast them as str
    _ips_to_add = list(map(str, ips_to_add))
    LOG.info("IP addresses have been changed, updating DNS records...")
    LOG.info(f"IPs to add: {', '.join(_ips_to_add)}")
    LOG.info(f"Record IDs to remove: {', '.join(record_ids_to_remove)}")
    with ProcessPoolExecutor() as pool:
        if ips_to_add:
            add_op_results = pool.map(add_record_func, _ips_to_add)
            failed_ips = [ip for ip, success in zip(_ips_to_add, add_op_results, strict=True) if not success]
            for ip in failed_ips:
                LOG.error(f"Failed to add DNS record for IP: {ip}")
        if record_ids_to_remove:
            remove_op_results = pool.map(delete_record_func, record_ids_to_remove)
            failed_record_ids = [
                record_id
                for record_id, success in zip(record_ids_to_remove, remove_op_results, strict=True)
                if not success
            ]
            for record_id in failed_record_ids:
                LOG.error(f"Failed to delete DNS record with ID: {record_id}")
    LOG.info("DNS records update completed.")


# --- Main function ---
def main() -> Literal[0, 1]:
    """Main function"""
    try:
        interface, nm_action, is_debug, config_path = parse_args()
        setup_logging(is_debug)

        # Only dhcp change and interface up/down events change IP addresses
        valid_events = ["dhcp4-change", "dhcp6-change", "up", "down", "connectivity-change"]
        if nm_action not in valid_events:
            LOG.warning(f"{nm_action} is not a addresses changing event, skipping ddns update")
            return 0
        if interface:
            LOG.info(f"{nm_action.replace('-', ' ')} event detected on {interface}.")
        else:
            LOG.info(f"{nm_action.replace('-', ' ')} event detected.")

        config = load_config(config_path)
        target_ips = get_global_ip_addresses()
        if not target_ips:
            LOG.warning("No global IP addresses found, exiting.")
            return 0
        LOG.info(f"Local global IP addresses: {', '.join(map(str, target_ips))}")

        all_dns_records = get_dns_records(config)

        LOG.debug(f"Current DNS records: {all_dns_records}")

        if all_dns_records is None:
            LOG.error("Could not retrieve DNS records, exiting.")
            return 1

        ips_to_add, record_ids_to_remove = determine_dns_actions(all_dns_records, target_ips)

        add_records_with_config = partial(add_dns_record, config=config)
        delete_records_with_config = partial(delete_dns_record, config=config)

        if not is_debug:
            wait_seconds = 3
            LOG.info(f"Waiting {wait_seconds} seconds before updating.")
            sleep(3)
        execute_dns_changes(
            ips_to_add,
            record_ids_to_remove,
            add_records_with_config,
            delete_records_with_config,
        )

    except Exception as e:
        LOG.critical(f"An unrecoverable error occurred: {e}.", exc_info=True)
        return 1
    else:
        return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception:
        LOG.exception("An unexpected error occurred.")
        exit(1)
