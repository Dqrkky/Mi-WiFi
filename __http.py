import requests
import json

class Request:
    def __init__(self):
        self.rss = requests.Session()
    def close(self):
        if self.rss != None:
            self.rss.close()
    def __enter__(self):
        return self
    def __exit__(**args):
        self.close()
        return True
    def request(self, config :dict | None=None):
        if config == None or isinstance(config, dict) == False:
            return
        return self.rss.request(
            **config
        )
    def requestJson(self, config :dict | None=None):
        if config == None or isinstance(config, dict) == False:
            return
        req = self.request(
            config=config
        )
        if req.headers.get("Content-Type", None) == None or isinstance(req.headers.get("Content-Type", None), str) == False or req.headers.get("Content-Type") != "applicaton/json":
            return
        return json.loads(
            s=req.content
        )