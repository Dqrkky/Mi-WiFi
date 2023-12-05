import requests
import hashlib
import time
import random
import shared

config2 = {
    "xqnetwork": {
        "lan_info": {
            "method": "get",
            "url": "{}/api/xqnetwork/lan_info"
        },
        "macbind_info": {
            "method": "get",
            "url": "{}/api/xqnetwork/macbind_info"
        },
        "ddns": {
            "method": "get",
            "url": "{}/api/xqnetwork/ddns"
        },
        "portforward": {
            "method": "get",
            "url": "{}/api/xqnetwork/portforward"
        },
        "dmz": {
            "method": "get",
            "url": "{}/api/xqnetwork/dmz"
        },
        "wifiap_signal": {
            "method": "get",
            "url": "{}/api/xqnetwork/wifiap_signal"
        },
        "wifi_list": {
            "method": "get",
            "url": "{}/api/xqnetwork/wifi_list"
        },
        "set_all_wifi": {
            "method": "get",
            "url": "{}/api/xqnetwork/set_all_wifi"
        },
        "check_wan_type": {
            "method": "get",
            "url": "{}/api/xqnetwork/check_wan_type"
        }
    },
    "misystem": {
        "devicelist": {
            "method": "get",
            "url": "{}/api/misystem/devicelist"
        },
        "sys_time": {
            "method": "get",
            "url": "{}/api/misystem/sys_time"
        },
        "qos_info": {
            "method": "get",
            "url": "{}/api/misystem/qos_info"
        },
        "smartvpn_info": {
            "method": "get",
            "url": "{}/api/misystem/smartvpn_info"
        },
        "mi_vpn_info": {
            "method": "get",
            "url": "{}/api/misystem/mi_vpn_info"
        },
        "set_router_name": {
            "method": "get",
            "url": "{}/api/misystem/set_router_name",
            "params": {
                "name": "Xiomi" 
            }
        },
        "newstatus": {
            "method": "get",
            "url": "{}/api/misystem/newstatus"
        },
        "status": {
            "method": "get",
            "url": "{}/api/misystem/status"
        },
        "messages": {
            "method": "get",
            "url": "{}/api/misystem/messages"
        },
        "sys_log": {
            "method": "get",
            "url": "{}/api/misystem/sys_log"
        },
        "get_elink": {
            "method": "get",
            "url": "{}/api/misystem/get_elink"
        },
        "router_info": {
            "method": "get",
            "url": "{}/api/misystem/router_info"
        },
        "bandwidth_test": {
            "method": "get",
            "url": "{}/api/misystem/bandwidth_test"
        },
        "c_backup": {
            "method": "get",
            "url": "{}/api/misystem/c_backup",
            "params": {
                "keys": "mi_basic_info,mi_network_info,mi_wifi_info,mi_lan_info,mi_arn_info"
            }
        }
    },
    "xqsystem": {
        "check_rom_update": {
            "method": "get",
            "url": "{}/api/xqsystem/check_rom_update"
        },
        "get_location": {
            "method": "get",
            "url": "{}/api/xqsystem/get_location"
        },
        "vpn": {
            "method": "get",
            "url": "{}/api/xqsystem/vpn"
        },
        "upnp": {
            "method": "get",
            "url": "{}/api/xqsystem/upnp"
        },
        "reboot": {
            "method": "get",
            "url": "{}/api/xqsystem/reboot"
        }
    },
    "misns": {
        "wifi_share_info": {
            "method": "get",
            "url": "{}/api/misns/wifi_share_info"
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
                }
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
                "url": f'{self.config["getaway"]}/api/xqnetwork/wifi_detail_all'
            }
            data = self.rss.request(
                *self.shared.convert_json_to_values(
                    config=config
                )
            ).json()
            if data != None and "code" in data and data["code"] != None and isinstance(data["code"], int) and data["code"] == 0:
                return data
    def wan_info(self):
        if "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/wan_info'
            }
            data = self.rss.request(
                *self.shared.convert_json_to_values(
                    config=config
                )
            ).json()
            if data != None and "code" in data and data["code"] != None and isinstance(data["code"], int) and data["code"] == 0:
                return data
    def pppoe_status(self):
        if "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/pppoe_status'
            }
            data = self.rss.request(
                *self.shared.convert_json_to_values(
                    config=config
                )
            ).json()
            if data != None and "code" in data and data["code"] != None and isinstance(data["code"], int) and data["code"] == 0:
                return data
    def wifi_macfilter_info(self):
        if "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/wifi_macfilter_info'
            }
            data = self.rss.request(
                *self.shared.convert_json_to_values(
                    config=config
                )
            ).json()
            if data != None and "code" in data and data["code"] != None and isinstance(data["code"], int) and data["code"] == 0:
                return data
    def lan_dhcp(self):
        if "getaway" in self.config and self.config["getaway"] != None:
            config = {
                "method": "get",
                "url": f'{self.config["getaway"]}/api/xqnetwork/lan_dhcp'
            }
            data = self.rss.request(
                *self.shared.convert_json_to_values(
                    config=config
                )
            ).json()
            if data != None and "code" in data and data["code"] != None and isinstance(data["code"], int) and data["code"] == 0:
                return data