from fastapi import requests
from fastapi import Request, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import aiohttp
from surge import get_surge_config, get_wg_section


app = FastAPI(
    title="Surge config helper for surfshark VPN",
    description="",
    version="v0.0.1",
)


@app.get("/surfshark.conf", response_class=HTMLResponse)
async def surge_conf(request: Request, private_key, self_ip:str, dns_server:str="162.252.172.57, 149.154.159.92",mtu:int= 1420, egress: str = "", standalone_proxy=""):
    async with aiohttp.ClientSession() as clientSession:
        async with clientSession.get("https://my.surfshark.com/vpn/api/v4/server/clusters") as resp:
            clusters = await resp.json()
            proxy = standalone_proxy + "\n" if standalone_proxy != "" else ""
            appendix = ""
            if egress != "":
                egress = f", {egress}"
            for cluster in clusters:
                peer = f'(public-key = {cluster["pubKey"]}, allowed-ips = "0.0.0.0/0, ::/0", endpoint = {cluster["connectionName"]}:51820)'
                section_id, section_detail = get_wg_section(
                    private_key=private_key,
                    self_ip=self_ip,
                    dns_server=dns_server,
                    mtu=mtu,
                    peer = peer
                )
                entry = f"{cluster['countryCode']}-{cluster['location'].replace(' ', '-').replace('.','')} = wireguard, section-name={section_id}, underlying-proxy=override_eg\n"
                proxy += entry
                appendix += section_detail + '\n'

            
            return get_surge_config(str(request.url), proxy, egress, appendix)

            