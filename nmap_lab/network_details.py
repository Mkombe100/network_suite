#requirements
#sudo apt install nmap iproute2 net-tools traceroute

import os
import re
import subprocess
from collections import OrderedDict

network = "172.30.114.0/24"

# scan network
output = subprocess.getoutput(f"nmap -sn {network}")

devices = OrderedDict()

for line in output.split("\n"):
    if "Nmap scan report for" in line:
        ip = line.split()[-1]
        devices[ip] = {"ip": ip}

    if "MAC Address" in line:
        mac = line.split()[2]
        devices[list(devices.keys())[-1]]["mac"] = mac

# fill missing fields
for ip in devices:
    try:
        hostname = subprocess.getoutput(f"nslookup {ip} | awk '/name =/ {{print $4}}'")
        devices[ip]["name"] = hostname.strip() if hostname else "-"
    except:
        devices[ip]["name"] = "-"

    # detect latency
    ping = subprocess.getoutput(f"ping -c 1 -W 1 {ip}")
    match = re.search(r'time=(\d+\.?\d*) ms', ping)
    devices[ip]["latency"] = match.group(1) if match else "N/A"

    # detect wired/wireless (your device only, not remote)
    devices[ip]["mode"] = "unknown"

# print table
print("| Name | IP | MAC | Latency(ms) | Mode |")
print("|------|----|-----|-------------|------|")

for d in devices.values():
    print(f"| {d.get('name','-')} | {d['ip']} | {d.get('mac','-')} | {d['latency']} | {d['mode']} |")
