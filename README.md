# Cloudflare DDNS NetworkManager dispatcher script

A Python Script to update Cloudflare DDNS record to current machine's IPv6 Address, with only python stdlib

## Usage

Firstly, create a config file `config.json` at /etc/NetworkManager/dispatcher.d/ddns

```json
{
  "email": "",
  "zone_id": "",
  "api_key": "",
  "domain_to_bind": ".cloud0310.cn"
}
```

where
`email` should be your cloudflare account's email
`zone_id` can be obtained with

```bash
curl https://api.cloudflare.com/client/v4/zones -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "Authorization: Bearer $CLOUDFLARE_API_KEY"
```

`domain_to_bind` should be the DDNS domain you want to bind to.

To manually trigger the script once. Please make sure the script's permission is executable, then you can use the command.

```bash
ddns-py <INTERFACE> <EVENT>
```

To get the log for debug

```bash
sudo systemctl status NetworkManager-dispatcher.service
```
