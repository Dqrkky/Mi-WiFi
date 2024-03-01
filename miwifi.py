import requests
import hashlib
import time
import json
import random
import shared

class Xiaomi:
    def __init__(self, host :str="http://router.miwifi.com", password :str=None):
        with requests.Session() as rss:
            self.rss = rss
        self.shared = shared.Shared(
            rss=self.rss
        )
        self.config = {
            "key": "a2ffa5c9be07488bbb04a3a47d3c5f6a",
            "mac_prefix": "e4:46:da",
            "host": host if host != None and isinstance(host, str) else None,
            "password": password if password != None and (isinstance(password, str) or isinstance(password, int)) else None,
            "getaway": None,
            "token": None
        }
    def request(self, config :dict=None):
        if config != None and isinstance(config, dict):
            req = self.rss.request(
                *self.shared.convert_json_to_values(
                    config=config
                )
            )
            if req != None and req.status_code == 200:
                return req
    def sha1(self=None, string :str=None):
        if string == None:
            return
        return hashlib.sha1(string.encode()).hexdigest()
    def get_random_mac(self=None, prefix :str=None):
        if prefix == None:
            return
        return prefix + ':'.join("%02x"%random.randint(0, 255) for _ in range(3))
    def get_nonce(self=None, mac_address :str=None):
        if mac_address == None:
            return
        return f"0_{mac_address}_{int(time.time())}_9999"
    def get_password_hash(self=None, nonce :str=None, password :str=None, key :str=None):
        if nonce == None:
            return
        if password == None:
            return
        if key == None:
            return
        return self.sha1(nonce + self.sha1(password + key))
    def login(self, host :str=None, password :str=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict):
            if host != None and isinstance(host, str):
                self.config["host"] = host
            if password != None and (isinstance(password, str) or isinstance(password, int)):
                self.config["password"] = password
            if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "host" in self.config and self.config["host"] != None and "password" in self.config and self.config["password"] != None:
                nonce = self.get_nonce(
                    mac_address=self.get_random_mac(
                        prefix=self.config["mac_prefix"]
                    )
                )
                config = {
                    "method": "post",
                    "url": f'{self.config["host"]}/cgi-bin/luci/api/xqsystem/login',
                    "params": {
                        "username": "admin",
                        "password": self.get_password_hash(
                            nonce=nonce,
                            password=self.config["password"],
                            key=self.config["key"]
                        ),
                        "nonce": nonce,
                        "logtype": 2
                    }
                }
                req = self.request(
                    config=config
                )
                if req != None:
                    data = req.json()
                    if data != None and "token" in data and data["token"] != None and isinstance(data["token"], str):
                        self.config["token"] = data["token"]
                        self.config["getaway"] = f'{self.config["host"]}/cgi-bin/luci/;stok={self.config["token"]}'
                        return {
                            "token": self.config["token"],
                            "getaway": self.config["getaway"]
                        }
    def wifi_detail_all(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/wifi_detail_all'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def wan_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/wan_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def pppoe_status(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/pppoe_status'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def wifi_macfilter_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/wifi_macfilter_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def lan_dhcp(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/lan_dhcp'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def lan_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/lan_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def macbind_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/macbind_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def ddns(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/ddns'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def portforward(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/portforward'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def dmz(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/dmz'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def wifiap_signal(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/wifiap_signal'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def wifi_list(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/wifi_list'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def set_all_wifi(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/set_all_wifi'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def check_wan_type(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/check_wan_type'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def mac_clone(self, mac_address :str=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None and mac_address != None and isinstance(mac_address, str):
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/mac_clone',
                "params": {
                    "mac": mac_address
                }
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def set_wan_speed(self, speed :int=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None and speed != None and isinstance(speed, int) and speed in [0, 100, 1000]:
            config = {
                "method": "post",
                "url": f'{self.config["getaway"]}/api/xqnetwork/set_wan_speed',
                "data": {
                    "speed": speed
                }
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def set_wan(self, wanType :str=None, pppoeName :str=None, pppoePwd :str=None, autoset :str=None, mtu :str=1480, service :str=None, dns1 :str=None, dns2 :str=None, staticIp :str=None, staticMask :str=None, staticGateway :str=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None and wanType != None and isinstance(wanType, str) and wanType in ["pppoe", "dhcp", "static"]:
            data = None
            if wanType == "pppoe" and pppoeName != None and isinstance(pppoeName, str) and pppoePwd != None and isinstance(pppoePwd, str) and autoset != None and isinstance(autoset, int):
                if autoset == 0:
                    data = {
                        "wanType": "pppoe",
                        "pppoeName": pppoeName,
                        "pppoePwd": pppoePwd,
                        "autoset": autoset
                    }
                elif autoset == 1 and mtu != None and isinstance(mtu, int) and service != None and isinstance(service, str) and dns1 != None and isinstance(dns1, str) and dns2 != None and isinstance(dns2, str):
                    data = {
                        "wanType": "pppoe",
                        "pppoeName": pppoeName,
                        "pppoePwd": pppoePwd,
                        "autoset": autoset,
                        "mtu": mtu,
                        "service": service,
                        "dns1": dns1,
                        "dns2": dns2
                    }
            elif wanType == "dhcp" and dns1 != None and isinstance(dns1, str) and dns2 != None and isinstance(dns2, str):
                if autoset == 1:
                    data = {
                        "wanType": wanType,
                        "autoset": autoset,
                        "dns1": dns1,
                        "dns2": dns2
                    }
            elif wanType == "static" and staticIp != None and isinstance(staticIp, str) and staticMask != None and isinstance(staticMask, str) and staticGateway != None and isinstance(staticGateway, str) and dns1 != None and isinstance(dns1, str) and dns2 != None and isinstance(dns2, str):
                data = {
                    "wanType": wanType,
                    "staticIp": staticIp,
                    "staticMask": staticMask,
                    "staticGateway": staticGateway,
                    "dns1": dns1,
                    "dns2": dns2
                }
            if data != None and isinstance(data, dict):
                config = {
                    "method": "post",
                    "url": f'{self.config["getaway"]}/api/xqnetwork/set_wan',
                    "data": json.dumps(data)
                }
                req = self.request(
                    config=config
                )
                if req != None:
                    return req.json()
    def devicelist(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/devicelist'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def sys_time(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/sys_time'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def qos_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/qos_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def smartvpn_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/smartvpn_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def mi_vpn_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/mi_vpn_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def set_router_name(self, name :str=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None and name != None and isinstance(name, str):
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/set_router_name',
                "params": {
                    "name": name
                }
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def newstatus(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/newstatus'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def status(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/status'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def messages(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/messages'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def sys_log(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/sys_log'
            }
            req = self.request(
                config=config
            )
            if req != None:
                data = req.json()
                if data != None and isinstance(data, dict):
                    if "path" in data and data["path"] != None and isinstance(data["path"], str):
                        if not data["path"].startswith("http"):
                            data["url"] = f'{self.config["getaway"].split(":")[0]}://{data["path"]}'
                            data.pop("path")
                    return data
    def get_elink(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/get_elink'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def router_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/router_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def bandwidth_test(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/bandwidth_test'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def c_backup(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misystem/c_backup',
                "params": {
                    "keys": ','.join([
                        "mi_basic_info",
                        "mi_network_info",
                        "mi_wifi_info",
                        "mi_lan_info",
                        "mi_arn_info"
                    ])
                }
            }
            req = self.request(
                config=config
            )
            if req != None:
                data = req.json()
                if data != None and isinstance(data, dict):
                    if "url" in data and data["url"] != None and isinstance(data["url"], str):
                        if not data["url"].startswith("http"):
                            data["url"] = f'{self.config["getaway"].split(":")[0]}://{data["url"]}'
                    return data
    def check_rom_update(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqsystem/check_rom_update'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def get_location(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqsystem/get_location'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def vpn(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqsystem/vpn'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def upnp(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqsystem/upnp'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def reboot(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqsystem/reboot'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def set_mac_filter(self, mac :str=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None and mac != None and isinstance(mac, str):
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqsystem/set_mac_filter',
                "params": {
                    "mac": mac,
                    "wan": 1
                }
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def wifi_share_info(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/misns/wifi_share_info'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()
    def nettb(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "host" in self.config and self.config["host"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["host"]}/cgi-bin/luci/api/xqnetdetect/nettb'
            }
            req = self.request(
                config=config
            )
            if req != None:
                return req.json()