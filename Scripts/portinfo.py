from scapy.all import *

TEMP_FILE_LOCATION = ".\\Scripts\\fileName.txt"

# Get The PCAP File Location
with open(TEMP_FILE_LOCATION) as f:
	PCAP_FILE = f.readline().replace("\n", "")

MY_PACKET = rdpcap(PCAP_FILE)

# Get Total Unique Network Ports
LIST_NET_PORT = []

for i in range(len(MY_PACKET)):
	try:
		CURRENT_PACKET = MY_PACKET[i]
		if CURRENT_PACKET.haslayer(IP):
			IP_PACKET = CURRENT_PACKET[IP].src
			if CURRENT_PACKET.haslayer(UDP) or CURRENT_PACKET.haslayer(TCP):
				LIST_NET_PORT.append(CURRENT_PACKET.sport)
	except:
		pass

LIST_NET_PORT.sort()

print("[+]  Total Network Port: {}\n".format(len(list(set(LIST_NET_PORT)))))

PORT_DICT = {m:LIST_NET_PORT.count(m) for m in LIST_NET_PORT}

if len(LIST_NET_PORT) == 0:
    print("No Network Port Found in The PCAP File")
else:
	for PORT_NUM, PORT_COUNT in PORT_DICT.items():
		print("Port:", str(PORT_NUM), " " * (8-len(str(PORT_NUM))), "Total Found:", str(PORT_COUNT))