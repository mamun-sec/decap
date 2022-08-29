from scapy.all import *
from scapy.all import rdpcap
import requests
import json

TEMP_FILE_LOCATION = ".\\Scripts\\fileName.txt"

# Get The PCAP File Location
with open(TEMP_FILE_LOCATION) as f:
    PCAP_FILE = f.readline().replace("\n", "")

# Get The PCAP File Conents
MY_PACKET = rdpcap(PCAP_FILE)

# Get Total Unique MAC Addresses
LIST_MAC_ADDR = []

for FRAME in MY_PACKET:
	try:
		PCAP_F = FRAME[Ether]
		LIST_MAC_ADDR.append(PCAP_F.src)
		LIST_MAC_ADDR.append(PCAP_F.dst)
	except:
		pass

UNIQE_MAC = list(set(LIST_MAC_ADDR))
UNIQE_MAC.sort()

print("[+]  Total MAC Address: {}".format(len(UNIQE_MAC)))
print("[+]  Getting MAC Address From macvendors.co API\n")

if len(UNIQE_MAC) == 0:
	print("No MAC Address Found in The PCAP File")
else:
	for x in range(len(UNIQE_MAC)):
		try:
			JSON_RESPONSE = requests.get("https://macvendors.co/api/{}/json".format(UNIQE_MAC[x])).json()
			TXT_RESPONSE = str(JSON_RESPONSE)
			if "error" in TXT_RESPONSE:
				print(UNIQE_MAC[x], "    Vendor Name: Not Found")
			else:
				COMPANY_NAME = TXT_RESPONSE.split("'company': '")[1].split("',")[0]
				print(UNIQE_MAC[x], "    Vendor Name:", COMPANY_NAME)
		except:
			pass