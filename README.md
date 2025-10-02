# Cloudflare DDNS NetworkManager dispatcher script

A Python Script to update Cloudflare DDNS record to current machine's IPv6 Address, with only python stdlib

## Usage

### Get your cloudflare API key

To get started with this project, you should get yourself a cloudflare API key
at [create API keys](https://dash.cloudflare.com/profile/api-tokens) first.

Just click the create token button, then choose "Edit zone DNS" template, choose
the dns zone you need to bind your IP address with.

After getting your API, create a config file `config.json` at directory `/etc/NetworkManager/dispatcher.d/ddns/`

```jsonc
{
  "email": "",
  "zone_id": "",
  "api_key": "",
  "domain_to_bind": "",
  "api_request_proxy": "", // optional, support socks5 or http proxy, for accessing Cloudflare API endpoint, won't affect the IP address getted.
}
```

where `email` should be your cloudflare account's email
`zone_id` can be obtained with

```bash
curl 'https://api.cloudflare.com/client/v4/zones' \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "Authorization: Bearer $CLOUDFLARE_API_KEY"
```

`domain_to_bind` should be the DDNS domain you want to bind to.

To get help info of the script:

```bash
ddns-py --help
```

To manually trigger the script once. Please make sure the script's permission is executable, then you can use the command.

```bash
ddns-py <INTERFACE> <EVENT>
```

To get the log for debug

```bash
sudo systemctl status NetworkManager-dispatcher.service
```
