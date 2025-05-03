# 🔍 Network Scanner using Python

A Python-based local network scanner that discovers devices connected to your network. It uses ARP requests to find active hosts and fetches MAC addresses along with their vendor/manufacturer information.

---

## 🚀 Features

- Scans a given IP range on the local network
- Retrieves IP address and MAC address of connected devices
- Looks up the manufacturer of each device using its MAC address
- Displays a clean tabular output
- Simple to run on any Linux system with Python support

---

## 🛠️ Technologies Used

- [`scapy`](https://scapy.readthedocs.io/en/latest/): for sending ARP requests
- [`getmac`](https://pypi.org/project/getmac/): for accessing MAC addresses
- [`mac-vendor-lookup`](https://pypi.org/project/mac-vendor-lookup/): for getting manufacturer details from MAC

---

## 📦 Requirements

Install the required Python libraries using the provided `requirements.txt`:

```bash
pip install -r requirements.txt
```

# How to Use:
```
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```
Step 2: Install Dependencies
```
pip install -r requirements.txt
```
Step 3: Run the Script
```
sudo python scanner.py
```
### Make sure to replace the ```ip_range``` in the script with your subnet, for example:
```
ip_range = "192.168.1.1/24"
```


------------------------------------------------------------------------------------------


# Sample Output:
```
IP Address           MAC Address                 Manufacturer
------------------------------------------------------------
192.168.1.2          A4:5E:60:XX:XX:XX           Apple, Inc.
192.168.1.10         B8:27:EB:XX:XX:XX           Raspberry Pi Foundation
...
```



# Disclaimer:
- This tool is intended for educational purposes only.
- Only scan networks you own or have explicit permission to access.
- Unauthorized scanning may be illegal in some regions.

# Author:
Github: [Manish Tiwari](https://github.com/PredictiveManish)


Feel Free to fork and modify and add other features!!
