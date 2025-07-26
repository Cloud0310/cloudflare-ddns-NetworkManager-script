#!/usr/bin/env python3

import json
import logging
import socket
from argparse import ArgumentParser
from ipaddress import IPv6Address
from os import environ
from sys import exit, stdout
from time import sleep
from urllib import error, parse, request

logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.StreamHandler(stdout)],
)

parser = ArgumentParser(
    "Cloudflare NetworkManager DDNS Updater",
    "ddns-py <INTERFACE> <EVENT>",
    "DDNS with your IPv6 address script with \
    'NetworkManager up / connectivity-change / dns-change' events.",
)

parser.add_argument(
    "INTERFACE",
    type=str,
)
parser.add_argument(
    "ACTION",
    type=str,
    choices=["up", "connectivity-change", "dns-change"],
    help="NetworkManager action to trigger the script.",
)


class CloudFlareDDNS:
    def __init__(self, auth_email: str, auth_key: str, zone_id: str, record_name: str):
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

    def _send_request(
        self, url: str, method: str, data: dict | None = None
    ) -> dict | None:
        body = json.dumps(data).encode("utf-8") if data else None

        logging.info(f"Using proxy {environ.get('http_proxy', 'None')}")
        req = request.Request(url, method=method, data=body)
        for key, value in self.headers.items():
            req.add_header(key, value)
        try:
            with request.urlopen(req) as response:
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

    def get_dns_record(self, name: str) -> list | None:
        """get DNS records for a given name and type.

        Args:
            name (str, optional): the DNS name to query.
            dns_type (str, optional): Defaults to "AAAA".

        Returns:
            list | None: a list of DNS records if found, None otherwise
        """
        params = parse.urlencode({"name": name})
        url = f"{self.endpoint}?{params}"
        response: dict | None = self._send_request(url, "GET")
        return response.get("result") if response else None

    def update_dns_record(self, record_id: str, record_name: str, content: str) -> bool:
        """update a DNS record with the given content.

        Args:
            record_id (str): the ID of the DNS record to update
            content (str): updated content for the DNS record

        Returns:
            bool: True if the update was successful, False otherwise
        """
        url = f"{self.endpoint}/{record_id}"
        data = {
            "type": "AAAA",
            "name": record_name,
            "content": content,
            "ttl": 1200,
            "proxied": False,
        }

        response: dict | None = self._send_request(url, "PUT", data)
        if response and response.get("success"):
            logging.info(f"DNS record updated successfully: {content}")
            return True
        else:
            logging.error("Failed to update DNS record")
            return False

    def add_dns_record(self, name: str, content: str) -> bool:
        """add a new DNS record with the given name and content.

        Args:
            name (str): the DNS name to add
            content (str): content for the new DNS record

        Returns:
            bool: True if the addition was successful, False otherwise
        """
        data = {
            "type": "AAAA",
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


def get_global_ipv6_addresses() -> list[IPv6Address] | None:
    """Get a list of IPv6 addresses for the local machine."""
    addr_info: list[
        tuple[
            socket.AddressFamily,
            socket.SocketKind,
            int,
            str,
            tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
        ]
    ] = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)

    all_ip_addresses: list[IPv6Address] = [
        IPv6Address(info[4][0]) for info in addr_info
    ]

    global_ipv6_addresses = list(
        filter(lambda v6_addr: v6_addr.is_global, set(all_ip_addresses)),
    )

    return global_ipv6_addresses if global_ipv6_addresses else None


def load_config(config_path: str = "config.json") -> dict:
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

    logging.info(f"Interface: {INTERFACE}, Action: {ACTION}")
    config = load_config(CONFIG_PATH)

    if not config:
        logging.error("Configuration is empty or invalid.")
        exit(1)

    logging.info("Waiting for network to stabilize..., 5s")
    sleep(5)
    ipv6_addresses = get_global_ipv6_addresses()
    if not ipv6_addresses:
        logging.error("No global IPv6 addresses found.")
        exit(1)
    logging.info(
        f"Global IPv6 addresses: {', '.join(str(addr) for addr in ipv6_addresses)}"
    )
    ipv6_address = ipv6_addresses[0]  # Use the first global IPv6 address
    logging.info(f"Using IPv6 address: {ipv6_address}")

    DDNS_client = CloudFlareDDNS(
        auth_email=config["email"],
        auth_key=config["api_key"],
        zone_id=config["zone_id"],
        record_name=config["domain_to_bind"],
    )
    dns_record = DDNS_client.get_dns_record(name=config["domain_to_bind"])

    if dns_record is None or dns_record == []:  # if record not found
        DDNS_client.add_dns_record(
            name=config["domain_to_bind"], content=str(ipv6_address)
        )
    else:  # found record, update it if necessary
        record = dns_record[0]
        record_address = record["content"]
        if record_address != str(ipv6_address):
            logging.info(
                f"Updating DNS record {config['domain_to_bind']} from {record_address} to {ipv6_address}"
            )
            DDNS_client.update_dns_record(
                record_id=record["id"],
                record_name=config["domain_to_bind"],
                content=str(ipv6_address),
            )
        else:
            logging.info(
                f"DNS record {config['domain_to_bind']} is already up-to-date with {ipv6_address}"
            )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)
