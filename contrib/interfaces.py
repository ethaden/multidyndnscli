import netifaces
#ADDR_TYPE=netifaces.AF_INET
ADDR_TYPE=netifaces.AF_INET6

for iface in netifaces.interfaces():
    addrs = netifaces.ifaddresses(iface)
    if ADDR_TYPE in addrs:
        print (f'Interface {iface}:')
        print (addrs[ADDR_TYPE])
