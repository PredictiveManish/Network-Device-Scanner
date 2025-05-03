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
