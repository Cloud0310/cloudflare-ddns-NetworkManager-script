#!/usr/bin/env python3

import json
import logging
from argparse import ArgumentParser
from concurrent.futures import ProcessPoolExecutor
from ipaddress import ip_address
from os import getenv
from shutil import which
from subprocess import check_output
from sys import exit, stdout
from time import sleep
from typing import Any
from urllib import error, parse, request


# colorful loggning formatter
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


parser = ArgumentParser(
    prog="ddns-py",
    usage="ddns-py INTERFACE ACTION",
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


class CloudFlareDDNS:
    def __init__(
        self,
        auth_email: str,
        auth_key: str,
        zone_id: str,
        proxy: str | None = None,
    ):
        self.auth_email = auth_email
        self.auth_key = auth_key
        self.zone_id = zone_id
        self.endpoint = (
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        ) # endpoint for managing DNS records
        self.headers = {
            "X-Auth-Email": auth_email,
            "Authorization": "Bearer " + auth_key,
            "Content-Type": "application/json",
        }
        self.proxy = proxy

    def _send_request(
        self, url: str, method: str, data: dict | None = None
    ) -> dict | None:
        body = json.dumps(data).encode("utf-8") if data else None

        if isinstance(self.proxy, str):
            logging.info(f"Using API request proxy: {self.proxy}")
            proxy_handler = request.ProxyHandler(
                {
                    "http": self.proxy,
                    "https": self.proxy,
                }
            )
            opener = request.build_opener(proxy_handler)
            request.install_opener(opener)

        req = request.Request(url, method=method, data=body, headers=self.headers)
        try:
            with request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    return json.loads(response.read().decode("utf-8"))
                else:
                    logging.error(f"Error {response.status}: {response.reason}")
                    return None
        except error.HTTPError as e:
            logging.error(f"HTTP error: {e.code} - {e.reason}")
            return None
        except error.URLError as e:
            logging.error(f"URL error: {e.reason}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error: {e.msg}")
            return None

    def get_dns_records(
        self, name: str, type: str
    ) -> list[dict[str, int | bool | str]] | None:
        """get DNS records for a given name and type.

        Args:
            name (str): the DNS name to query.
            type (str): "A" for IPv4 or "AAAA" for IPv6, must be within ["A", "AAAA"]

        Returns:
            list | None: a list of DNS records if found, None otherwise
        """

        if type not in ["A", "AAAA"]:
            logging.error("Invalid type, must be 'A' or 'AAAA'")
            return None

        params = parse.urlencode({"name": name, "type": type})
        url = f"{self.endpoint}?{params}"
        response: dict | None = self._send_request(url, "GET")
        return response.get("result") if response else None

    def add_dns_record(self, name: str, content: str) -> bool:
        """add a new DNS record with the given name and content.

        Args:
            name: (str): the DNS name to add, e.g. "example.com"
            content (str): content for the new DNS record

        Returns:
            bool: True if the addition was successful, False otherwise
        """
        logging.debug(f"Adding DNS record: {name} -> {content}")

        data = {
            "type": ip_address(content).version == 4 and "A" or "AAAA",
            "name": name,
            "content": content,
            "ttl": 1,  # Setting to 1 means 'automatic'
            "proxied": False,
        }

        response: dict | None = self._send_request(self.endpoint, "POST", data)
        if response and response.get("success"):
            logging.info(f"DNS record added successfully: {name} -> {content}")
            return True
        else:
            logging.error("Failed to add DNS record")
            return False

    def delete_dns_record(self, record_id: str) -> bool:
        """delete a DNS record by its ID.

        Args:
            record_id (str): the ID of the DNS record to delete

        Returns:
            bool: True if the deletion was successful, False otherwise
        """
        logging.debug(f"Deleting DNS record with ID: {record_id}")
        url = f"{self.endpoint}/{record_id}"
        response: dict | None = self._send_request(url, "DELETE")
        if response and response.get("success"):
            logging.info(f"DNS record {record_id} deleted successfully.")
            return True
        else:
            logging.error(f"Failed to delete DNS record {record_id}.")
            return False


def get_global_ip_addresses(interface: str) -> list[str]:
    """get global (public) IPv4 and IPv6 addresses for a given network interface.

    Args:
        interface (str): the network interface to query, e.g. "eth0", optional. If None, check all interfaces.

    Returns:
        IPAddresses: a dataclass containing lists of global IPv4 and IPv6 addresses
    """
    ip_path = which("ip")
    if not ip_path:
        logging.error("'ip' command not found. Please install iproute2 package.")
        exit(1)

    # use 'ip -json addr show' to get all IP addresses in JSON format, more reliable than socket.getaddrinfo
    args: list[str] = [ip_path, "-j", "addr", "show"]
    if (
        interface == "" or interface == "none"
    ):  # For the hostname action the device name is always "none". For connectivity-change and dns-change it is empty.
        logging.warning("No network interface specified, check all the interfaces.")
    else:
        logging.info(f"Checking IP addresses for interface: {interface}")
        args.append(interface)

    try:
        out = check_output(args)
    except Exception as e:
        logging.error(f"Failed to execute 'ip' command: {e}")
        exit(1)

    data: list[dict[str, Any]] = json.loads(out)
    addr_infos: list[list[dict[str, Any]]] = [
        addr_info for iface in data for addr_info in iface.get("addr_info", [])
    ]  # flatten the list of lists

    # filter out deprecated addresses and private addresses
    global_ip_addresses = [
        addr_info["local"]
        for addr_info in addr_infos
        if not (
            ip_address(addr_info["local"]).is_private
            or addr_info.get("deprecated")  # ignore deprecated IPv6 addresses
        )
    ]

    if not any(ip_address(ip).version == 4 for ip in global_ip_addresses):
        logging.warning("No global IPv4 address found.")
    if not any(ip_address(ip).version == 6 for ip in global_ip_addresses):
        logging.warning("No global IPv6 address found.")

    return global_ip_addresses


def load_config(config_path: str = "config.json") -> dict[str, Any]:
    """Load configuration from a JSON file."""
    try:
        with open(config_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        logging.error(f"Configuration file {config_path} not found.")
        exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {config_path}: {e.msg}")
        exit(1)


def main():
    args = parser.parse_args()
    INTERFACE = args.INTERFACE.strip()
    ACTION = args.ACTION.strip()
    IS_DEBUG = getenv("DEBUG") == "1"
    CONFIG_PATH = (
        "/etc/NetworkManager/dispatcher.d/ddns/config.json"
        if not IS_DEBUG
        else "./ddns/config.json"
    )  # use a local config file for debugging

    console_handler = logging.StreamHandler(stdout)
    console_handler.setFormatter(CustomFormatter())

    logger = logging.getLogger(__name__)

    logger.setLevel(logging.DEBUG if IS_DEBUG else logging.INFO)
    logger.addHandler(console_handler)

    if not IS_DEBUG:
        logging.info("Waiting for network to stabilize..., 5s")
        sleep(5)

    logging.info(
        f"Interface: {INTERFACE}, Action: {ACTION}, config path: {CONFIG_PATH}"
    )
    config = load_config(CONFIG_PATH)

    if not config:
        logging.error("Configuration is empty or invalid.")
        exit(1)

    ip_addresses = get_global_ip_addresses(INTERFACE)

    if ip_addresses == []:
        logging.error("No global IP addresses found to bind.")
        exit(1)
    else:
        logging.info(
            f"Found global IP addresses {', '.join([ip_address for ip_address in ip_addresses])}"
        )

    DDNS_client = CloudFlareDDNS(
        auth_email=config["email"],
        auth_key=config["api_key"],
        zone_id=config["zone_id"],
        proxy=config["api_request_proxy"],
    )

    ipv4_records = DDNS_client.get_dns_records(name=config["domain_to_bind"], type="A")
    ipv6_records = DDNS_client.get_dns_records(
        name=config["domain_to_bind"], type="AAAA"
    )
    dns_records = (ipv4_records or []) + (ipv6_records or [])

    local_ips = {ip for ip in ip_addresses}
    ips_on_cloudflare = {record.get("content") for record in dns_records}

    if ips_on_cloudflare == local_ips:
        logging.info("No change in IP addresses, no update needed.")
        exit(0)

    logging.debug(f"Local IPs: {local_ips}, Cloudflare IPs: {ips_on_cloudflare}")
    logging.info("IP addresses have changed, updating DNS records...")

    ips_to_add = local_ips - ips_on_cloudflare
    ips_to_remove = ips_on_cloudflare - local_ips

    # Delete old DNS records that are no longer valid, in parallel
    with ProcessPoolExecutor() as pool:
        records_to_remove = [
            record["id"] for record in dns_records if record["content"] in ips_to_remove
        ]
        results = pool.map(
            DDNS_client.delete_dns_record,
            records_to_remove,
        )
        for record, success in zip(records_to_remove, results):
            if not success:
                logging.error(f"Failed to delete DNS record with ID: {record['id']}")

    # Add new DNS records for the new IP addresses, in parallel
    with ProcessPoolExecutor() as pool:
        results = pool.map(
            DDNS_client.add_dns_record,
            [[config["domain_to_bind"]] * len(ips_to_add), list(ips_to_add)],
        )
        for ip, success in zip(ips_to_add, results):
            if not success:
                logging.error(f"Failed to add DNS record for IP: {ip}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)
