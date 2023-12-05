import miwifi

mw = miwifi.Xiaomi( 
    password="02335566"
)

print(mw.login())
print(mw.check_wan_type())