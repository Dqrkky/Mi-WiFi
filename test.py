import miwifi

mw = miwifi.Xiaomi(
    password="023355"
)

print(mw.login())
print(mw.wifi_detail_all())