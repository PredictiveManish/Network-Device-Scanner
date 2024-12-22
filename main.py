import scapy.all as scapy
from mac_vendor_lookup import MacLookup  # Corrected import
from getmac import get_mac_address

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        try:
            lookup = MacLookup()
            manufacturer = lookup.lookup(device_info["mac"])
        except:
            manufacturer = "Unknown"
            
        device_info["Manufacturer"] = manufacturer
        devices.append(device_info)
    return devices

def display_devices(devices):
    print("IP Address\t\tMAC Address\t\t\tManufacturer")
    print("-"*60)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['Manufacturer']}")

ip_range = "10.14.50.1/24"
devices = scan_network(ip_range)

display_devices(devices)
