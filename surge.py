import random
import hashlib
def get_surge_config(url, proxy="", egress_override="", appendix=""):
    proxies = ",".join([i.split("=")[0] for i in proxy.splitlines()])
    return f"""#!MANAGED-CONFIG {url} interval=86400 strict=false
[General]
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.1, localhost, *.local
ipv6 = true
test-timeout = 5
loglevel = notify

[Proxy]
{proxy}

[Proxy Group]
override_eg = select, DIRECT{egress_override}
auto = url-test, {proxies}, url=http://www.gstatic.com/generate_204 ,interval=300

[Rule]
FINAL,DIRECT

{appendix}

"""

def get_wg_section(private_key, peer, self_ip, prefer_ipv6="true", dns_server="162.252.172.57, 149.154.159.92", mtu=1420):
    section_id = hashlib.md5(peer.encode('latin-1')).hexdigest().upper()[:8]
    return section_id, f"""[WireGuard {section_id}]
private-key = {private_key}
self-ip = {self_ip}
prefer-ipv6 = {prefer_ipv6}
dns-server = {dns_server}
mtu = {mtu}
peer = {peer}
"""