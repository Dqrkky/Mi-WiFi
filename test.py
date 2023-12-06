import miwifi

mw = miwifi.Xiaomi( 
    password="02335566"
)

print(mw.login())
print(mw.set_wan_speed(speed=1000))