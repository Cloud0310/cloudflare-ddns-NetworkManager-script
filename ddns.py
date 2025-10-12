#!/usr/bin/env python3

import json
import logging
from argparse import ArgumentParser
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from functools import partial
from ipaddress import ip_address
from itertools import chain
from os import getenv
from shutil import which
from subprocess import CalledProcessError, check_output
from sys import exit, stdout
from time import sleep
from typing import Literal
from urllib import error, parse, request


@dataclass
class Config:
    email: str
    api_key: str
    zone_id: str
    domain_to_bind: str
    api_request_proxy: str | None


# colorful logging formatter
class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    )

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setup_logging(is_debug: bool):
    """Setup logging configuration.

    Args:
        is_debug (bool): If True, set logging level to DEBUG, else INFO.
    """
    log_level = logging.DEBUG if is_debug else logging.INFO
    handler = logging.StreamHandler(stdout)
    handler.setFormatter(CustomFormatter())
    logging.basicConfig(level=log_level, handlers=[handler])
    logging.debug("Debug mode is enabled.")


def parse_args() -> tuple[str, str, bool, str]:
    """Parse command line arguments.

    Returns:
        Tuple[str, str, bool, str]: INTERFACE, ACTION, IS_DEBUG, CONFIG_PATH
    """
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
    args = parser.parse_args()
    is_debug = getenv("DEBUG") == "1"
    config_path = (
        "/etc/NetworkManager/dispatcher.d/ddns/config.json"
        if not is_debug
        else "./ddns/config.json"  # use a local config file for debugging
    )
    return args.INTERFACE.strip(), args.ACTION.strip(), is_debug, config_path


def calculate_dns_changes(
    current_ips: set[str], desired_ips: set[str]
) -> tuple[set[str], set[str]]:
    """Calculate which IPs need to be added and which need to be removed.
    Args:
        current_ips (set[str]): The set of currently configured IPs.
        desired_ips (set[str]): The set of desired IPs.
    Returns:
        Tuple[set[str], Set[str]]: A tuple containing two sets:
            - The first set contains IPs to be added.
            - The second set contains IPs to be removed.
    """
    ips_to_add = desired_ips - current_ips
    ips_to_remove = current_ips - desired_ips
    return ips_to_add, ips_to_remove


def load_config(config_path: str = "config.json") -> Config:
    """Load configuration from a JSON file.
    Args:
        config_path (str, optional): Path to the configuration file. Defaults to "config.json".
    Returns:
        Config: The loaded configuration as a Config object.
    """
    try:
        with open(config_path, "r") as file:
            data = json.load(file)
            config = Config(
                email=data["email"],
                api_key=data["api_key"],
                zone_id=data["zone_id"],
                domain_to_bind=data["domain_to_bind"],
                api_request_proxy=data.get("proxy"),
            )
            logging.debug(f"Configuration loaded from {config_path}")
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file {config_path} not found.")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {config_path}: {e.msg}")
        raise


def get_global_ip_addresses(interface: str | None) -> list[str]:
    """Get global (public) IPv4 and IPv6 addresses for a given network interface.

    Args:
        interface (str | None): the network interface to query, e.g. "eth0", optional. If None, check all interfaces.

    Returns:
        list[str]: a list of global IP addresses
    """
    ip_route_path = which("ip")
    if not ip_route_path:
        raise FileNotFoundError(
            "'ip' command not found. Please install iproute2 package."
        )
    args: list[str] = [ip_route_path, "-j", "addr", "show"]
    if interface and interface != "none":
        logging.info(f"Checking IP addresses for interface: {interface}")
        args.append(interface)
    else:
        logging.warning("No network interface specified, check all the interfaces.")
    try:
        out = check_output(args)
    except CalledProcessError as e:
        raise RuntimeError(f"Failed to execute 'ip' command: {e}") from e

    data: list[dict[str, any]] = json.loads(out)

    addr_infos: list[dict[str, any]] = list(
        chain.from_iterable(map(lambda iface: iface.get("addr_info", []), data))
    )

    def is_valid_global(info):
        return ip_address(info["local"]).is_global and not info.get("deprecated", False)

    global_ip_addresses = list(
        map(lambda info: info["local"], filter(is_valid_global, addr_infos))
    )

    # Warn if no global IPv4 or IPv6 address is found
    if not any(ip_address(ip).version == 4 for ip in global_ip_addresses):
        logging.warning("No global IPv4 address found.")
    if not any(ip_address(ip).version == 6 for ip in global_ip_addresses):
        logging.warning("No global IPv6 address found.")

    return global_ip_addresses


def _send_api_request(
    config: Config, url: str, method: str, data: dict[str, any] | None = None
) -> dict[str, any] | None:
    """Send an API request to Cloudflare.

    Args:
        config (Config): Configuration object containing authentication details.
        url (str): The API endpoint URL.
        method (str): HTTP method (e.g., "GET", "POST", "DELETE")
        data (dict[str, any] | None, optional): The request payload. Defaults to None.

    Returns:
        dict[str, any] | None: The response data in JSON format, or None if an error occurred.
    """
    headers = {
        "X-Auth-Email": config.email,
        "Authorization": "Bearer " + config.api_key,
        "Content-Type": "application/json",
    }
    body = json.dumps(data).encode("utf-8") if data else None

    proxy = config.api_request_proxy
    if proxy is not None:
        proxy_handler = request.ProxyHandler(
            {
                "http": config.api_request_proxy,
                "https": config.api_request_proxy,
            }
        )
        opener = request.build_opener(proxy_handler)
        request.install_opener(opener)
        logging.info(f"Using proxy for API requests: {config.api_request_proxy}")

    req = request.Request(url, method=method, data=body, headers=headers)
    try:
        with request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                return json.loads(response.read().decode("utf-8"))
            else:
                logging.error(f"Error {response.status}: {response.reason}")
                return None
    except (error.HTTPError, error.URLError, json.JSONDecodeError) as e:
        logging.error(f"API request error: {e}")
        return None


def get_dns_records(
    config: Config, domain_name: str, type: str
) -> list[dict[str, int | bool | str]] | None:
    """Get DNS records for a given type.

    Args:
        config (Config): Configuration object containing authentication details.
        domain_name (str): The domain name to query.
        type (str): "A" for IPv4 or "AAAA" for IPv6, must be within ["A", "AAAA"]

    Returns:
        list | None: a list of DNS records if found, None otherwise
    """

    if type not in ["A", "AAAA"]:
        logging.error("Invalid type, must be 'A' or 'AAAA'")
        return None

    endpoint = (
        f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/dns_records"
    )
    params = parse.urlencode({"name": domain_name, "type": type})
    url = f"{endpoint}?{params}"
    response: dict[str, any] | None = _send_api_request(config, url, "GET")
    return response.get("result") if response else None


def add_dns_record(config: Config, content: str) -> bool:
    """Add a new DNS record with the given name and content.

    Args:
        config (Config): Configuration object containing authentication details.
        content (str): content for the new DNS, usually an IP address.

    Returns:
        bool: True if the addition was successful, False otherwise
    """
    logging.debug(f"Adding DNS record: {config.domain_to_bind} -> {content}")

    endpoint = (
        f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/dns_records"
    )
    data = {
        "type": ip_address(content).version == 4 and "A" or "AAAA",
        "name": config.domain_to_bind,
        "content": content,
        "ttl": 1,  # Setting to 1 means 'automatic'
        "proxied": False,
    }

    response: dict[str, any] | None = _send_api_request(config, endpoint, "POST", data)
    if response and response.get("success"):
        logging.info(
            f"DNS record added successfully: {config.domain_to_bind} -> {content}"
        )
        return True
    else:
        logging.error("Failed to add DNS record")
        return False


def delete_dns_record(config: Config, record_id: str) -> bool:
    """Delete a DNS record by its ID.

    Args:
        config (Config): Configuration object containing authentication details.
        record_id (str): the ID of the DNS record to delete

    Returns:
        bool: True if the deletion was successful, False otherwise
    """
    logging.debug(f"Deleting DNS record with ID: {record_id}")
    endpoint = (
        f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/dns_records"
    )
    url = f"{endpoint}/{record_id}"
    response: dict[str, any] | None = _send_api_request(config, url, "DELETE")
    if response and response.get("success"):
        logging.info(f"DNS record {record_id} deleted successfully.")
        return True
    else:
        logging.error(f"Failed to delete DNS record {record_id}.")
        return False


# --- Main function ---
def main() -> Literal[0, 1]:
    """Main function"""
    try:
        interface, action, is_debug, config_path = parse_args()
        setup_logging(is_debug)
        if not is_debug:
            logging.info("Waiting for network to be stabilize... 2s")
            sleep(2)  # wait for the network to be fully up
        # loading configuration (side effect)
        config = load_config(config_path)
        local_ips = set(get_global_ip_addresses(interface))
        logging.info(f"Local global IP addresses: {', '.join(local_ips)}")
        if not local_ips:
            logging.error("No global IP addresses found, exiting.")
            return 1
        logging.info(f"Found Local IPs: {', '.join(local_ips)}")

        # Fetch current DNS records
        ipv4_records = get_dns_records(config, config.domain_to_bind, "A") or []
        ipv6_records = get_dns_records(config, config.domain_to_bind, "AAAA") or []
        all_records = ipv4_records + ipv6_records
        current_ips = {record["content"] for record in all_records}

        # Calculate changes
        ips_to_add, ips_to_remove = calculate_dns_changes(current_ips, local_ips)

        # apply changes in parallel
        if not (ips_to_add or ips_to_remove):
            logging.info("No changes needed, exiting.")
            return 0

        logging.info("IP addresses have been changed, updating DNS records...")
        logging.debug(
            f"Current IPs: {', '.join(current_ips)}, Desired IPs: {', '.join(local_ips)}"
        )
        logging.debug(
            f"IPs to add: {', '.join(ips_to_add)}, IPs to remove: {', '.join(ips_to_remove)}"
        )

        add_records_with_config = partial(add_dns_record, config)
        delete_records_with_config = partial(delete_dns_record, config)

        with ProcessPoolExecutor() as pool:
            if ips_to_add:
                pool.map(add_records_with_config, ips_to_add)
            if ips_to_remove:
                record_ids_to_remove = [
                    record["id"]
                    for record in all_records
                    if record["content"] in ips_to_remove
                ]
                pool.map(delete_records_with_config, record_ids_to_remove)

        logging.info("DNS records update completed.")
        return 0
    except Exception as e:
        logging.critical(f"An unrecoverable error occurred: {e}.", exc_info=True)
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)
