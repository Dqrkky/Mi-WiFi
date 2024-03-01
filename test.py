import miwifi
import cacheDump
import requests

mw = miwifi.Xiaomi(
    password=""
)



print(mw.login())

url = mw.sys_log()["url"]
ch = cacheDump.File(url.split("/")[-1].replace("-", "_").replace(":", "_"))
ch.write(requests.get(url).content)
tg = cacheDump.Zip(ch.path())
print(tg.list())