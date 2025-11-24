# Cloudflare DDNS for NetworkManager

A lightweight, dependency-free Python script that automatically updates your Cloudflare DNS records with your machine's public IP addresses. It's designed to run as a [NetworkManager dispatcher](https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html) script, making it ideal for servers or desktops with dynamic IPs.

## TODOs

- Use pytest for coverage showing and better code structure
- Async Updates
- Adding support for systemd udev based detection, unbind the NetworkManager
  vendor

## Features

- **Automatic Updates**: Integrates seamlessly with NetworkManager to update DNS records on network events (like `up`, `connectivity-change`).
- **IPv4 and IPv6 Support**: Automatically detects and syncs both public IPv4 (A records) and IPv6 (AAAA records).
- **No External Dependencies**: Uses only the Python standard library. No `pip install` required.
- **Robust IP Detection**: Reliably finds global IP addresses using the modern `ip -j addr` command.
- **Proxy Support**: Can route Cloudflare API requests through an HTTP or SOCKS5 proxy.
- **Efficient**: Only updates Cloudflare if it detects that your IP address has actually changed.
- **100% Test Coverage**: robust by test
- **Functional Programming**: easy to debug and maintain

## Prerequisites

- A Linux system using NetworkManager.
- Python 3.6+ installed.
- The `iproute2` package (which provides the `ip` command), which is standard on most modern Linux distributions.
- A Cloudflare account and a domain managed by it.

## Installation

1.  **Place the Script and Make it Executable**

    Copy the `ddns-py` script to the NetworkManager dispatcher directory. It's good practice to name it in a way that controls execution order, for example, `99-cf-ddns`.

    ```bash
    sudo cp ddns.py /etc/NetworkManager/dispatcher.d/99-cf-ddns
    ```

    > [!note]
    > The script must have execute permissions to be run by NetworkManager.

1.  **Create the Configuration Directory**

    The script looks for its configuration in a subdirectory.

    ```bash
    sudo mkdir -p /etc/NetworkManager/dispatcher.d/ddns
    ```

1.  **Create the Configuration File**

    Create your configuration file at `/etc/NetworkManager/dispatcher.d/ddns/config.json`.

    ```bash
    sudo nano /etc/NetworkManager/dispatcher.d/ddns/config.json
    ```

    Paste and fill out the following template:

    ```json
    {
      "email": "your-cloudflare-email@example.com",
      "zone_id": "your_zone_id_from_cloudflare",
      "api_key": "your_cloudflare_api_token",
      "domain_to_bind": "subdomain.yourdomain.com",
      "api_request_proxy": ""
    }
    ```

## Configuration Details

- **`email`**: The email address associated with your Cloudflare account.
- **`api_key`**: Your Cloudflare API Token.
  - Go to **My Profile > API Tokens** > **[Create Token](https://dash.cloudflare.com/profile/api-tokens)**.
  - Use the "**Edit zone DNS**" template.
  - Under "Zone Resources", select the specific zone you want to grant access to.
  - Create the token and copy the key.
- **`zone_id`**: The ID of the DNS zone containing your domain. You can find this on the "Overview" page for your domain in the Cloudflare dashboard, or by running this command:
  ```bash
  curl -X GET "https://api.cloudflare.com/client/v4/zones" \
       -H "X-Auth-Email: YOUR_CLOUDFLARE_EMAIL" \
       -H "Authorization: Bearer YOUR_CLOUDFLARE_API_TOKEN"
  ```
- **`domain_to_bind`**: The full DNS record name you want to update (e.g., `home.example.com`).
- **`api_request_proxy`** (Optional): If you need to use a proxy to reach the Cloudflare API, specify it here.
  - Format: `http://user:pass@host:port` or `socks5://host:port`.
  - Leave as an empty string (`""`) if not needed.

## Usage

### Automatic (via NetworkManager)

Once installed and configured, the script will run automatically whenever NetworkManager detects a relevant network change. No further action is needed.

### Manual Execution (for Testing)

You can trigger the script manually to test your configuration. NetworkManager normally passes two arguments: the interface and the action.

> [!note]
> The debug config should be located at `.\ddns\config.json`

```bash
# Example: Manually trigger for the 'eth0' interface with an 'up' event
sudo ./ddns-py.py eth0 up
```

For more detailed logs during manual testing, set the `DEBUG` environment variable:

```bash
sudo DEBUG=1 ./ddns-py.py eth0 up
```

## Troubleshooting

Logs from NetworkManager dispatcher scripts are typically sent to the system journal. You can view them with `journalctl` or `systemctl status NetworkManager-dispatcher`.

```bash
# View the live logs from the NetworkManager dispatcher
sudo journalctl -u NetworkManager-dispatcher.service -f
```

Look for output from the `99-cf-ddns` script to diagnose any issues.
