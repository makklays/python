from scapy.all import ARP, Ether, srp, conf

conf.verb = 0

def arp_scan(network, iface):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, iface=iface)[0]

    devices = []
    for _, received in result:
        devices.append((received.psrc, received.hwsrc))
    return devices


if __name__ == "__main__":
    iface = "wlo1"
    network = "192.168.0.0/24"

    devices = arp_scan(network, iface)

    print("Найденные устройства:")
    for ip, mac in devices:
        print(f"IP: {ip}, MAC: {mac}")

