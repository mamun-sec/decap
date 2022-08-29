from scapy.all import *
from scapy.all import rdpcap
from scapy.layers.inet import IP
from OTXv2 import OTXv2
import IndicatorTypes
import sys
import re


# Declare Variables
otx = OTXv2("f96f9093d66e53e85a1f09a5894d2b8c7d9a8533f6e8b05f5df92c1179d5423e")
TEMP_FILE_LOCATION = ".\\Scripts\\fileName.txt"

# Get The PCAP File Location
with open(TEMP_FILE_LOCATION) as f:
    PCAP_FILE = f.readline().replace("\n", "")


def PCAP_GET_PCAP_URL(payload):
    PCAP_HEAD_REGEX = r"(?P<name>.*?): (?P<value>.*?)\r\n"
    PCAP_BEGIN = payload.index(b"GET ") +4
    PCAP_END = payload.index(b" HTTP/1.1")
    PCAP_PCAP_URL_PATH = payload[PCAP_BEGIN:PCAP_END].decode("utf8")
    PCAP_RAW_HEAD = payload[:payload.index(b"\r\n\r\n") + 2 ]
    PCAP_PARSED_HEAD = dict(re.findall(PCAP_HEAD_REGEX, PCAP_RAW_HEAD.decode("utf8")))
    PCAP_URL = PCAP_PARSED_HEAD["Host"] + PCAP_PCAP_URL_PATH + "\n"
    return PCAP_URL


# Get Total Unique PCAP_URL
LIST_URL_ADDR = []

MY_PACKET = rdpcap(PCAP_FILE)
sessions = MY_PACKET.sessions()
for session in sessions:
    for packet in sessions[session]:
        try:
            if packet[TCP].dport == 80 or packet[TCP].dport == 443:
                payload = bytes(packet[TCP].payload)
                PCAP_URL = PCAP_GET_PCAP_URL(payload)
                LIST_URL_ADDR.append(PCAP_URL.encode().decode().split("/")[0])
        except Exception as e:
            pass


UNIQE_URL = list(set(LIST_URL_ADDR))
UNIQE_URL.sort()

print("[+]  Total HTTP URL: {}".format(len(UNIQE_URL)))
print("[+]  Checking If Any OTX Pulse Found for The URL")
print("[+]  Decap Scans Only The Base Domain\n")

if len(UNIQE_URL) == 0:
    print("No HTTP URL Found in The PCAP File")
else:
    for x in range(len(UNIQE_URL)):
        try:
            OTX_RESULT = str(otx.get_indicator_details_full(IndicatorTypes.URL, UNIQE_URL[x]))
            if "pulse_source" in OTX_RESULT:
                print("URL:        ", UNIQE_URL[x], "\nOTX Pulse:   Found\n")
            else:
                print("URL:        ", UNIQE_URL[x], "\nOTX Pulse:   Not Found\n")
        except:
            pass