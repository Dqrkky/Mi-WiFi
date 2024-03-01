import miwifi
import cacheDump
import requests

mw = miwifi.Xiaomi(
    password=""
)



print(mw.login())

syslog = mw.sys_log()

for file in cacheDump.Zip(bytes_=requests.get(syslog["url"]).content).list():
    print(f'File : {file["name"]}\nContent : {file["content"].decode("utf-8")}\n\n')