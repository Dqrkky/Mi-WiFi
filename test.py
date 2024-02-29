import miwifi

mw = miwifi.Xiaomi(
    host="192.168.31.1",
    password="02335566"
)

print(mw.login())
print(mw.lan_info())