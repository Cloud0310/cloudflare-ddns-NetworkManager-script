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
from typing import Callable, Literal, Sequence
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


def setup_logging(is_debug: bool, logger: logging.Logger) -> None:
    """Setup logging configuration.

    Args:
        is_debug (bool): If True, set logging level to DEBUG, else INFO.
        logger: The logger instance to configure.
    """
    log_level = logging.DEBUG if is_debug else logging.INFO
    handler = logging.StreamHandler(stdout)
    handler.setFormatter(CustomFormatter())

    logger.setLevel(log_level)
    logger.addHandler(handler)
    logging.debug("Debug mode is enabled.")


def parse_args(args: Sequence[str] | None = None) -> tuple[str, str, bool, str]:
    """Parse Command Line Args

    Args:
        args (Sequence[str] | None, optional): System args. Defaults to None.

    Returns:
        tuple[str, str, bool, str]: A tuple containing:
            - INTERFACE (str): Network interface that triggered the script.
            - ACTION (str): NetworkManager action to trigger the script.
            - is_debug (bool): True if DEBUG environment variable is set to "1".
            - config_path (str): Path to the configuration file.
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
    args = parser.parse_args(args)
    is_debug = getenv("DEBUG") == "1"
    config_path = (
        "/etc/NetworkManager/dispatcher.d/ddns/config.json"
        if not is_debug
        else "./ddns/config.json"  # use a local config file for debugging
    )
    return args.INTERFACE.strip(), args.ACTION.strip(), is_debug, config_path


def load_config(logger: logging.Logger, config_path: str = "config.json") -> Config:
    """Load configuration from a JSON file.
    Args:
        logger (logging.Logger): Logger instance for logging messages.
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
            logger.debug(f"Configuration loaded from {config_path}")
            return config
    except FileNotFoundError:
        logger.error(f"Configuration file {config_path} not found.")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {config_path}: {e.msg}")
        raise


def get_global_ip_addresses(interface: str | None, logger: logging.Logger) -> list[str]:
    """Get global (public) IPv4 and IPv6 addresses for a given network interface.

    Args:
        interface (str | None): the network interface to query, e.g. "eth0", optional. If None, check all interfaces.

    Returns:
        list[str]: a list of global IP addresses
        logging.Logger: Logger instance for logging messages.
    """
    ip_route_path = which("ip")
    if not ip_route_path:
        raise FileNotFoundError(
            "'ip' command not found. Please install iproute2 package."
        )
    args: list[str] = [ip_route_path, "-j", "addr", "show"]
    if (
        interface and interface != "none"
    ):  # Network Manager may pass "none" or "" as interface
        logger.info(f"Checking IP addresses for interface: {interface}")
        args.append(interface)
    else:
        logger.warning("No network interface specified, check all the interfaces.")
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
        logger.warning("No global IPv4 address found.")
    if not any(ip_address(ip).version == 6 for ip in global_ip_addresses):
        logger.warning("No global IPv6 address found.")

    return global_ip_addresses


def build_api_request(
    config: Config,
    method: Literal["GET", "POST", "DELETE"],
    logger: logging.Logger,
    subpath: dict[str, str] | None = None,
    params: str | None = None,
    data: dict[str, any] | None = None,
) -> request.Request:
    """Build an API request to Cloudflare.

    Args:
        config (Config): Configuration object containing authentication details.
        method (Literal["GET", "POST", "DELETE"]): HTTP method.
        logger (logging.Logger): Logger instance for logging messages.
        params (str | None): encoded URL parameters to append to the endpoint, optional.
        subpath (str | None): API endpoint subpath, optional.
        data (dict[str, any] | None, optional): The request payload, optional.

    Returns:
        request.Request: a Request object if the request was successful, None otherwise
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
        logger.info(f"Using proxy for API requests: {config.api_request_proxy}")

    endpoint = (
        f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/dns_records"
    )
    url = f"{endpoint}/{subpath}" if subpath else endpoint
    url = f"{url}?{params}" if params else url

    req = request.Request(url, method=method, data=body, headers=headers)

    return req


# impure function to handle Network IO
def parse_api_response(
    req: request.Request, logger: logging.Logger
) -> dict[str, any] | None:
    """Open and parse the API response.

    Args:
        req (request.Request): A request Object

    Returns:
        dict[str, any] | None: The reponse data in json format
        logger (logging.Logger): Logger instance for logging messages.
    """
    try:
        with request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                return json.loads(response.read().decode("utf-8"))
            else:
                logger.error(f"Error {response.status}: {response.reason}")
                return None
    except (error.HTTPError, error.URLError, json.JSONDecodeError) as e:
        logger.error(f"API request error: {e}")
        return None


def get_dns_records(
    config: Config, logger: logging.Logger
) -> list[dict[str, int | bool | str]] | None:
    """Get DNS records of type "A" and "AAAA".

    Args:
        config (Config): Configuration object containing zone_id and domain_to_bind.

    Returns:
        list | None: a list of DNS records if found, None otherwise.
        logger (logging.Logger): Logger instance for logging messages.
    """

    params = parse.urlencode({"name": config.domain_to_bind})

    req: dict[str, any] | None = build_api_request(
        config,
        method="GET",
        logger=logger,
        params=params,
    )

    response = parse_api_response(req, logger)

    # fliter the records to only include A and AAAA types
    if response and response.get("success"):
        filtered_records = list(
            filter(lambda r: r["type"] in ("A", "AAAA"), response.get("result", []))
        )
        logger.debug(
            f"Fetched {len(filtered_records)} DNS records for {config.domain_to_bind}"
        )
        return filtered_records
    else:
        logger.error("Failed to fetch DNS records")
        return None


def add_dns_record(config: Config, content: str, logger: logging.Logger) -> bool:
    """Add a new DNS record with the given name and content.

    Args:
        config (Config): Configuration object containing authentication details.
        content (str): content for the new DNS, usually an IP address.
        logger (logging.Logger): Logger instance for logging messages.

    Returns:
        bool: True if the addition was successful, False otherwise
    """
    logger.debug(f"Adding DNS record: {config.domain_to_bind} -> {content}")

    data = {
        "type": "A" if ip_address(content).version == 4 else "AAAA",
        "name": config.domain_to_bind,
        "content": content,
        "ttl": 1,  # Setting to 1 means 'automatic'
        "proxied": False,
    }

    req = build_api_request(
        config, method="POST", subpath=None, params=None, data=data, logger=logger
    )
    resp = parse_api_response(req, logger)

    if resp and resp.get("success"):
        logger.info(
            f"DNS record added successfully: {config.domain_to_bind} -> {content}"
        )
        return True
    else:
        logger.error("Failed to add DNS record")
        return False


def delete_dns_record(config: Config, record_id: str, logger: logging.Logger) -> bool:
    """Delete a DNS record by its ID.

    Args:
        config (Config): Configuration object containing authentication details.
        record_id (str): the ID of the DNS record to delete
        logger (logging.Logger): Logger instance for logging messages.

    Returns:
        bool: True if the deletion was successful, False otherwise
    """
    logger.debug(f"Deleting DNS record with ID: {record_id}")
    req = build_api_request(
        config, method="DELETE", subpath=record_id, params=None, logger=logger
    )
    response = parse_api_response(req.logger)
    if response and response.get("success"):
        logger.info(f"DNS record {record_id} deleted successfully.")
        return True
    else:
        logger.error(f"Failed to delete DNS record {record_id}.")
        return False


def determine_dns_actions(
    all_dns_records: list[dict[str, any]], desired_ips: set[str]
) -> tuple[set[str], set[str]]:
    """Determine which DNS records need to be added or removed.

    Args:
        all_dns_records (list[dict[str, any]]): List of current DNS records.
        desired_ips (set[str]): Set of desired IP addresses.

    Returns:
        tuple[set[str], set[str]]: A tuple containing two sets:
            - ips_to_add (set[str]): IP addresses that need to be added as DNS records
            - record_ids_to_remove (set[str]): DNS record ids that need to be removed from DNS records
    """
    current_ips: set[str] = {record["content"] for record in all_dns_records}

    ips_to_add = desired_ips - current_ips
    ips_to_remove = current_ips - desired_ips
    record_ids_to_remove: set[str] = {
        record["id"] for record in all_dns_records if record["content"] in ips_to_remove
    }
    return ips_to_add, record_ids_to_remove


def execute_dns_changes(
    ips_to_add: set[str],
    record_ids_to_remove: list[str],
    add_record_func: Callable[[str], bool],
    delete_record_func: Callable[[str], bool],
    logger: logging.Logger,
) -> None:
    """Execute DNS changes in parallel using ProcessPoolExecutor.

    Args:
        ips_to_add (set[str]): Set of IP addresses to add as DNS records.
        record_ids_to_remove (list[str]): List of DNS record IDs to remove.
        add_record_func (Callable[[str], bool]): Function to add a DNS record.
        delete_record_func (Callable[[str], bool]): Function to delete a DNS record.
        logger (logging.Logger): Logger instance for logging messages.
    """
    if not (ips_to_add or record_ids_to_remove):
        logger.info("No DNS changes needed.")
        return
    logger.info("IP addresses have been changed, updating DNS records...")
    logger.debug(f"IPs to add: {', '.join(ips_to_add)}")
    logger.debug(f"Record IDs to remove: {', '.join(record_ids_to_remove)}")
    with ProcessPoolExecutor() as pool:
        if ips_to_add:  # pragma: no branch, already checked
            pool.map(add_record_func, ips_to_add)
        if record_ids_to_remove:  # pragma: no branch, already checked
            pool.map(delete_record_func, record_ids_to_remove)
    logger.info("DNS records update completed.")


# --- Main function ---
def main() -> Literal[0, 1]:
    """Main function"""
    try:
        interface, action, is_debug, config_path = parse_args()
        logger = logging.getLogger("ddns")
        setup_logging(is_debug, logger)
        if not is_debug:
            logger.info("Waiting for network to be stabilize... 2s")
            sleep(3)  # wait for the network to be fully up

        config = load_config(logger, config_path)
        target_ips = set(get_global_ip_addresses(interface, logger))
        if not target_ips:
            logger.warning("No global IP addresses found, exiting.")
            return 0
        else:
            logger.info(f"Local global IP addresses: {', '.join(target_ips)}")

        all_records = get_dns_records(config, logger)

        logger.debug(f"Current DNS records: {all_records}")

        if all_records is None:
            logger.error("Could not retrieve DNS records, exiting.")
            return 1

        ips_to_add, record_ids_to_remove = determine_dns_actions(
            all_records, target_ips
        )

        add_records_with_config = partial(add_dns_record, config=config, logger=logger)
        delete_records_with_config = partial(
            delete_dns_record, config=config, logger=logger
        )

        execute_dns_changes(
            ips_to_add,
            record_ids_to_remove,
            add_records_with_config,
            delete_records_with_config,
            logger,
        )

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
