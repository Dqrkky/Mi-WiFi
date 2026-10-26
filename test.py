import miwifi
import cacheDump
import requests
import dotenv
import time

data = dotenv.dotenv_values()

mw = miwifi.Xiaomi(
    host=data.get("HOST", None),
    password=data.get("PASSWORD", None)
)
while True:
    print(mw.status().get("cpu"))
    time.sleep(1)
# syslog = mw.sys_log()

# print(
#     next((
#         f
#         for f in cacheDump.Zip(
#             bytes_=requests.request(**{
#                 "method": "get",
#                 "url": syslog["url"]
#             }).content
#         ).list()
#         if f["name"] == "tmp/iptables_save.log"
#     ), None).get("content", b"").decode("utf-8")
# )
# leases_file = next((
#     f
#     for f in cacheDump.Zip(
#         bytes_=requests.request(**{
#             "method": "get",
#             "url": syslog["url"]
#         }).content
#     ).list()
#     if f["name"] == "tmp/dhcp.leases"
# ), None)

# if leases_file:
#     content = leases_file["content"].decode("utf-8")
#     devices = [
#         {
#             "duid": data[4],
#             "nane": data[3],
#             "ip": data[2],
#             "mac": data[1],
#             "tl": data[0]
#         }
#         for device in content.splitlines()
#         if len(data := device.split(" ")) > 2
#     ]
#     print(devices)
# else:
#     print("File not found")