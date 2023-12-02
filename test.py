import miwifi


mw = miwifi.Xiaomi(
    password="02335566"
)

print(mw.login())
print(mw.wifi_detail_all())