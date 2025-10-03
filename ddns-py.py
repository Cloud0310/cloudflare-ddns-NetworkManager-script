#!/usr/bin/env python3

import json
import logging
from argparse import ArgumentParser
from ipaddress import IPv4Address, IPv6Address, ip_address
from os import getenv
from subprocess import check_output
from sys import exit, stdout
from time import sleep
from typing import Any
from urllib import error, parse, request

logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.StreamHandler(stdout)],
)

parser = ArgumentParser(
    "Cloudflare NetworkManager DDNS Updater",
    "ddns-py <INTERFACE> <EVENT>",
    (
        "DDNS with your IPv6 address script with 'NetworkManager"
        "up / connectivity-change / dns-change' events."
    ),
)

parser.add_argument(
    "INTERFACE",
    type=str,
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
        record_name: str,
        proxy: str | None = None,
    ):
        self.auth_email = auth_email
        self.auth_key = auth_key
        self.zone_id = zone_id
        self.endpoint = (
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )
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

    def get_dns_record(self, name: str) -> list[dict[str, Any]] | None:
        """get DNS records for a given name and type.

        Args:
            name (str, optional): the DNS name to query.

        Returns:
            list | None: a list of DNS records if found, None otherwise
        """
        params = parse.urlencode({"name": name})
        url = f"{self.endpoint}?{params}"
        response: dict | None = self._send_request(url, "GET")
        return response.get("result") if response else None

    def add_dns_record(self, name: str, ip_version: str, content: str) -> bool:
        """add a new DNS record with the given name and content.

        Args:
            name: (str): the DNS name to add, e.g. "example.com"
            ip_version (str): "A" for IPv4 or "AAAA" for IPv6, must be within ["A", "AAAA"]
            content (str): content for the new DNS record

        Returns:
            bool: True if the addition was successful, False otherwise
        """

        data = {
            "type": ip_version,
            "name": name,
            "content": content,
            "ttl": 1200,
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
        url = f"{self.endpoint}/{record_id}"
        response: dict | None = self._send_request(url, "DELETE")
        if response and response.get("success"):
            logging.info(f"DNS record {record_id} deleted successfully.")
            return True
        else:
            logging.error(f"Failed to delete DNS record {record_id}.")
            return False


def get_global_ip_addresses(interface: str = None) -> list[IPv4Address | IPv6Address]:
    """get global (public) IPv4 and IPv6 addresses for a given network interface.

    Args:
        interface (str): the network interface to query, e.g. "eth0", optional. If None, check all interfaces.

    Returns:
        IPAddresses: a dataclass containing lists of global IPv4 and IPv6 addresses
    """
    # use 'ip -json addr show' to get all IP addresses in JSON format, more reliable than socket.getaddrinfo
    args: list[str] = ["/usr/bin/ip", "-j", "addr", "show"]
    if interface is None or interface == "":
        logging.warning("No network interface specified, check all the interfaces.")
        out = check_output(args)
    else:
        logging.info(f"Checking IP addresses for interface: {interface}")
        args.append(interface)
        out = check_output(args)
    data: list[dict[str, Any]] = json.loads(out)
    addr_infos: list[list[dict[str, Any]]] = [
        addr_info for iface in data for addr_info in iface.get("addr_info", [])
    ]  # flatten the list of lists

    # filter out deprecated addresses and private addresses
    global_ip_addresses = [
        ip_address(addr_info["local"])
        for addr_info in addr_infos
        if not ip_address(addr_info["local"]).is_private or addr_info.get("deprecated")
    ]

    if any(isinstance(ip, IPv4Address) for ip in global_ip_addresses) is False:
        logging.warning("No global IPv4 address found.")
    if any(isinstance(ip, IPv6Address) for ip in global_ip_addresses) is False:
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
    CONFIG_PATH = "/etc/NetworkManager/dispatcher.d/ddns/config.json"

    logging.info(
        f"Interface: {INTERFACE}, Action: {ACTION}, config path: {CONFIG_PATH}"
    )
    config = load_config(CONFIG_PATH)

    if not config:
        logging.error("Configuration is empty or invalid.")
        exit(1)

    if not getenv("DEBUG") == "1":
        logging.info("Waiting for network to stabilize..., 5s")
        sleep(5)

    ip_addresses = get_global_ip_addresses(INTERFACE)

    if ip_addresses == []:
        logging.error("No global IP addresses found to bind.")
        exit(1)
    else:
        logging.info(f"Found global IP addresses {str(*ip_addresses)}")

    DDNS_client = CloudFlareDDNS(
        auth_email=config["email"],
        auth_key=config["api_key"],
        zone_id=config["zone_id"],
        record_name=config["domain_to_bind"],
        proxy=config["api_request_proxy"],
    )

    dns_record = DDNS_client.get_dns_record(name=config["domain_to_bind"])

    # if these is existing DNS record(s), delete them first then update all with new IP address(es) to KEEP the DNS records in sync with current IP address(es)
    is_no_dns_record = True if (dns_record is None or dns_record == []) else False

    if not is_no_dns_record:
        logging.info(f"Existing DNS records found: {dns_record}, deleting them first.")
        for record in dns_record:
            record_id = record["id"]
            if record_id:
                success = DDNS_client.delete_dns_record(record_id=record_id)
                if not success:
                    logging.error(f"Failed to delete DNS record with ID: {record_id}")

    # add new DNS records with current IP addresses
    for ip in ip_addresses:
        ip_version = "A" if isinstance(ip, IPv4Address) else "AAAA"
        logging.info(f"Adding new record {config['domain_to_bind']} -> {ip}")
        success = DDNS_client.add_dns_record(
            name=config["domain_to_bind"],
            ip_version=ip_version,
            content=str(ip),
        )
        if not success:
            logging.error("Failed to add new DNS record.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)
