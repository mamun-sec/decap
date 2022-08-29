from scapy.all import *
import os

TEMP_FILE_LOCATION = ".\\Scripts\\fileName.txt"

# Get The PCAP File Location
with open(TEMP_FILE_LOCATION) as f:
	PCAP_FILE = f.readline().replace("\n", "")

if os.path.isfile(TEMP_FILE_LOCATION):
	os.remove(TEMP_FILE_LOCATION)

print("\n[+]  Scan Completed on Total {} Network Packets\n".format(len(rdpcap(PCAP_FILE))))