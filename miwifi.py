import requests
import hashlib
import time
import random
import shared

config2 = {
    "xqnetwork": {
        "wan_info": {
            "method": "get",
            "url": "{}/api/xqnetwork/wan_info",
            "aftermethod": "json"
        },
        "pppoe_status": {
            "method": "get",
            "url": "{}/api/xqnetwork/pppoe_status",
            "aftermethod": "json"
        },
        "wifi_macfilter_info": {
            "method": "get",
            "url": "{}/api/xqnetwork/wifi_macfilter_info",
            "aftermethod": "json"
        },
        "lan_dhcp": {
            "method": "get",
            "url": "{}/api/xqnetwork/lan_dhcp",
            "aftermethod": "json"
        },
        "lan_info": {
            "method": "get",
            "url": "{}/api/xqnetwork/lan_info",
            "aftermethod": "json"
        },
        "macbind_info": {
            "method": "get",
            "url": "{}/api/xqnetwork/macbind_info",
            "aftermethod": "json"
        },
        "ddns": {
            "method": "get",
            "url": "{}/api/xqnetwork/ddns",
            "aftermethod": "json"
        },
        "portforward": {
            "method": "get",
            "url": "{}/api/xqnetwork/portforward",
            "aftermethod": "json"
        },
        "dmz": {
            "method": "get",
            "url": "{}/api/xqnetwork/dmz",
            "aftermethod": "json"
        },
        "wifiap_signal": {
            "method": "get",
            "url": "{}/api/xqnetwork/wifiap_signal",
            "aftermethod": "json"
        },
        "wifi_list": {
            "method": "get",
            "url": "{}/api/xqnetwork/wifi_list",
            "aftermethod": "json"
        },
        "set_all_wifi": {
            "method": "get",
            "url": "{}/api/xqnetwork/set_all_wifi",
            "aftermethod": "json"
        },
        "check_wan_type": {
            "method": "get",
            "url": "{}/api/xqnetwork/check_wan_type",
            "aftermethod": "json"
        }
    },
    "misystem": {
        "devicelist": {
            "method": "get",
            "url": "{}/api/misystem/devicelist",
            "aftermethod": "json"
        },
        "sys_time": {
            "method": "get",
            "url": "{}/api/misystem/sys_time",
            "aftermethod": "json"
        },
        "qos_info": {
            "method": "get",
            "url": "{}/api/misystem/qos_info",
            "aftermethod": "json"
        },
        "smartvpn_info": {
            "method": "get",
            "url": "{}/api/misystem/smartvpn_info",
            "aftermethod": "json"
        },
        "mi_vpn_info": {
            "method": "get",
            "url": "{}/api/misystem/mi_vpn_info",
            "aftermethod": "json"
        },
        "set_router_name": {
            "method": "get",
            "url": "{}/api/misystem/set_router_name",
            "aftermethod": "json"
        },
        "newstatus": {
            "method": "get",
            "url": "{}/api/misystem/newstatus",
            "aftermethod": "json"
        },
        "status": {
            "method": "get",
            "url": "{}/api/misystem/status",
            "aftermethod": "json"
        },
        "messages": {
            "method": "get",
            "url": "{}/api/misystem/messages",
            "aftermethod": "json"
        },
        "sys_log": {
            "method": "get",
            "url": "{}/api/misystem/sys_log",
            "aftermethod": "json"
        },
        "get_elink": {
            "method": "get",
            "url": "{}/api/misystem/get_elink",
            "aftermethod": "json"
        },
        "router_info": {
            "method": "get",
            "url": "{}/api/misystem/router_info",
            "aftermethod": "json"
        }
    },
    "xqsystem": {
        "check_rom_update": {
            "method": "get",
            "url": "{}/api/xqsystem/check_rom_update",
            "aftermethod": "json"
        },
        "get_location": {
            "method": "get",
            "url": "{}/api/xqsystem/get_location",
            "aftermethod": "json"
        },
        "vpn": {
            "method": "get",
            "url": "{}/api/xqsystem/vpn",
            "aftermethod": "json"
        },
        "upnp": {
            "method": "get",
            "url": "{}/api/xqsystem/upnp",
            "aftermethod": "json"
        },
        "reboot": {
            "method": "get",
            "url": "{}/api/xqsystem/reboot",
            "aftermethod": "json"
        }
    },
    "misns": {
        "wifi_share_info": {
            "method": "get",
            "url": "{}/api/misns/wifi_share_info",
            "aftermethod": "json"
        }
    },
    "xqnetdetect": {
        "nettb": {
            "method": "get",
            "url": "/cgi-bin/luci/api/xqnetdetect/nettb"
        }
    }
}

class Xiaomi:
    def __init__(self, host :str="router.miwifi.com", password :str=None):
        with requests.Session() as rss:
            self.rss = rss
        self.shared = shared.Shared(
            rss=self.rss
        )
        self.config = {
            "key": "a2ffa5c9be07488bbb04a3a47d3c5f6a",
            "mac_prefix": "e4:46:da",
            "host": None,
            "password": None,
            "getaway": None,
            "token": None
        }
        if host != None and isinstance(host, str):
            self.config["host"] = host
        if password != None and (isinstance(password, str) or isinstance(password, int)):
            self.config["password"] = password
    def sha1(self=None, string :str=None):
        if string == None:
            return
        return hashlib.sha1(string.encode()).hexdigest()
    def get_random_mac(self=None, prefix :str=None):
        if prefix != None:
            return prefix + ':'.join("%02x"%random.randint(0, 255) for _ in range(3))
    def get_nonce(self=None, mac_address :str=None):
        if mac_address != None:
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
        if host != None and isinstance(host, str):
            self.config["host"] = host
        if password != None and (isinstance(password, str) or isinstance(password, int)):
            self.config["password"] = password
        if "host" in self.config and self.config["host"] != None and "password" in self.config and self.config["password"] != None:
            nonce = self.get_nonce(
                mac_address=self.get_random_mac(
                    prefix=self.config["mac_prefix"]
                )
            )
            config = {
                "method": "post",
                "url": f'http://{self.config["host"]}/cgi-bin/luci/api/xqsystem/login',
                "params": {
                    "username": "admin",
                    "password": self.get_password_hash(
                        nonce=nonce,
                        password=self.config["password"],
                        key=self.config["key"]
                    ),
                    "nonce": nonce,
                    "logtype": 2
                },
                "aftermethod": "json"
            }
            data = self.rss.request(
                *self.shared.convert_json_to_values(
                    config=config
                )
            ).json()
            if data != None and "token" in data and data["token"] != None and isinstance(data["token"], str):
                self.config["token"] = data["token"]
                self.config["getaway"] = f'http://{self.config["host"]}/cgi-bin/luci/;stok={self.config["token"]}'
                return {
                    "token": self.config["token"],
                    "getaway": self.config["getaway"]
                }
    def wifi_detail_all(self):
            if "getaway" in self.config and self.config["getaway"] != None:
                config = {
                    "method": "get",
                    "url": f'{self.config["getaway"]}/api/xqnetwork/wifi_detail_all',
                    "aftermethod": "json"
                }
                data = self.rss.request(
                    *self.shared.convert_json_to_values(
                        config=config
                    )
                ).json()
                if data != None and "info" in data and data["info"] != None and isinstance(data["info"], list):
                    return data["info"]