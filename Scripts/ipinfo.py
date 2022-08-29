from scapy.all import rdpcap
from scapy.layers.inet import IP
from OTXv2 import OTXv2
import IndicatorTypes

# Declare Variables
otx = OTXv2("f96f9093d66e53e85a1f09a5894d2b8c7d9a8533f6e8b05f5df92c1179d5423e")
TEMP_FILE_LOCATION = ".\\Scripts\\fileName.txt"

# Get The PCAP File Location
with open(TEMP_FILE_LOCATION) as f:
	PCAP_FILE = f.readline().replace("\n", "")

# Get The PCAP File Conents
MY_PACKET = rdpcap(PCAP_FILE)

# Get Total Unique IP Addresses
LIST_IP_ADDR = []

for i in range(len(MY_PACKET)):
	try:
		CURRENT_PACKET = MY_PACKET[i]
		IP_HEADER = CURRENT_PACKET[IP]

		CURRENT_IP = IP_HEADER.src
		LIST_IP_ADDR.append(CURRENT_IP)

		CURRENT_IP = IP_HEADER.dst
		LIST_IP_ADDR.append(CURRENT_IP)
	except:
		pass

UNIQE_IP = list(set(LIST_IP_ADDR))
UNIQE_IP.sort()

print("[+]  Total IP Address: {}".format(len(UNIQE_IP)))
print("[+]  Checking If Any OTX Pulse Found for The IP Address")
print("[+]  IP Address Might Be Suspicious If OTX Pulse Found\n")


# Check OTX Pulse Existence for The IP Addresses
if len(UNIQE_IP) == 0:
    print("No IP Address Found in The PCAP File")
else:
	for x in range(len(UNIQE_IP)):
		try:
			OTX_RESULT = str(otx.get_indicator_details_full(IndicatorTypes.IPv4, UNIQE_IP[x]))
			if "pulse_source" in OTX_RESULT:
				print(UNIQE_IP[x], " " * (17 - len(UNIQE_IP[x])), "OTX Pulse Found: Yes")
			else:
				print(UNIQE_IP[x], " " * (17 - len(UNIQE_IP[x])), "OTX Pulse Found: No")
		except:
			pass