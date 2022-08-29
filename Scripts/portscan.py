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

UNIQE_NET_PORT = list(set(LIST_NET_PORT))

print("[+]  Checking Existence of Network Ports Which Are Used by Malicious Actors:\n")

if len(UNIQE_NET_PORT) == 0:
	print("No Network Port Found in The PCAP File")
else:
	if 20 in UNIQE_NET_PORT:
		print("Port 20        Found        (Used for File Transfer)")
	else:
		print("Port 20        Not Found    (Used for File Transfer)")
	if 22 in UNIQE_NET_PORT:
		print("Port 22        Found        (Used for Remote Access)")
	else:
		print("Port 22        Not Found    (Used for SSH Remote Access)")
	if 23 in UNIQE_NET_PORT:
		print("Port 23        Found        (Used for SSH Remote Computer Access)")
	else:
		print("Port 23        Not Found    (Used for Remote Computer Access)")
	if 53 in UNIQE_NET_PORT:
		print("Port 53        Found        (Used for DNS Tunneling)")
	else:
		print("Port 53        Not Found    (Used for DNS Tunneling)")
	if 104 in UNIQE_NET_PORT:
		print("Port 104       Found        (Used by DICOM Medical X-Ray Machines)")
	else:
		print("Port 104       Not Found    (Used by DICOM Medical X-Ray Machines)")
	if 111 in UNIQE_NET_PORT:
		print("Port 111       Found        (Used for Remote Procedure Calls)")
	else:
		print("Port 111       Not Found    (Used for Remote Procedure Calls)")
	if 135 in UNIQE_NET_PORT:
		print("Port 135       Found        (Used by SQL Server)")
	else:
		print("Port 135       Not Found    (Used by SQL Server)")
	if 137 in UNIQE_NET_PORT:
		print("Port 137       Found        (Used by NetBIOS)")
	else:
		print("Port 137       Not Found    (Used by NetBIOS)")
	if 138 in UNIQE_NET_PORT:
		print("Port 138       Found        (Used by NetBIOS)")
	else:
		print("Port 138       Not Found    (Used by NetBIOS)")
	if 139 in UNIQE_NET_PORT:
		print("Port 139       Found        (Used to Access Network File Share)")
	else:
		print("Port 139       Not Found    (Used to Access Network File Share)")
	if 161 in UNIQE_NET_PORT:
		print("Port 161       Found        (Used by Siemens Industrial Automation)")
	else:
		print("Port 161       Not Found    (Used by Siemens Industrial Automation)")
	if 445 in UNIQE_NET_PORT:
		print("Port 445       Found        (Used to Access Network File Share and NAS Device)")
	else:
		print("Port 445       Not Found    (Used to Access Network File Share and NAS Device)")
	if 623 in UNIQE_NET_PORT:
		print("Port 623       Found        (Used for Remote Access by Intel Active Management)")
	else:
		print("Port 623       Not Found    (Used for Remote Access by Intel Active Management)")
	if 664 in UNIQE_NET_PORT:
		print("Port 664       Found        (Used for Remote Access by Intel Active Management)")
	else:
		print("Port 664       Not Found    (Used for Remote Access by Intel Active Management)")
	if 1194 in UNIQE_NET_PORT:
		print("Port 1194      Found        (Used by OpenVPN)")
	else:
		print("Port 1194      Not Found    (Used by OpenVPN)")
	if 1433 in UNIQE_NET_PORT:
		print("Port 1433      Found        (Used by SQL Server)")
	else:
		print("Port 1433      Not Found    (Used by SQL Server)")
	if 1434 in UNIQE_NET_PORT:
		print("Port 1434      Found        (Used by SQL Server)")
	else:
		print("Port 1434      Not Found    (Used by SQL Server)")
	if 1604 in UNIQE_NET_PORT:
		print("Port 1604      Found        (Used by Citrix Virtual Apps)")
	else:
		print("Port 1604      Not Found    (Used by Citrix Virtual Apps)")
	if 1723 in UNIQE_NET_PORT:
		print("Port 1723      Found        (Used by Microsoft PPTP VPN)")
	else:
		print("Port 1723      Not Found    (Used by Microsoft PPTP VPN)")
	if 1900 in UNIQE_NET_PORT:
		print("Port 1900      Found        (Used by HP iLO 4)")
	else:
		print("Port 1900      Not Found    (Used by HP iLO 4)")
	if 2375 in UNIQE_NET_PORT:
		print("Port 2375      Found        (Used by Docker APIs)")
	else:
		print("Port 2375      Not Found    (Used by Docker APIs)")
	if 3306 in UNIQE_NET_PORT:
		print("Port 3306      Found        (Used for MySQL)")
	else:
		print("Port 3306      Not Found    (Used for MySQL)")
	if 3389 in UNIQE_NET_PORT:
		print("Port 3389      Found        (Used for Remote Desktop Access)")
	else:
		print("Port 3389      Not Found    Used for Remote Desktop Access)")
	if 4022 in UNIQE_NET_PORT:
		print("Port 4022      Found        (Used by SQL Server)")
	else:
		print("Port 4022      Not Found    (Used by SQL Server)")
	if 5353 in UNIQE_NET_PORT:
		print("Port 5353      Found        (Used by Apple AirPlay Receiver)")
	else:
		print("Port 5353      Not Found    (Used by Apple AirPlay Receiver)")
	if 5432 in UNIQE_NET_PORT:
		print("Port 5432      Found        (Used by PostgreSQL Database)")
	else:
		print("Port 5432      Not Found    (Used by PostgreSQL Database)")
	if 5555 in UNIQE_NET_PORT:
		print("Port 5555      Found        (Used by Android Debug Bridge)")
	else:
		print("Port 5555      Not Found    (Used by Android Debug Bridge)")
	if 5601 in UNIQE_NET_PORT:
		print("Port 5601      Found        (Used by Kibana)")
	else:
		print("Port 5601      Not Found    (Used by Kibana)")
	if 5800 in UNIQE_NET_PORT:
		print("Port 5800      Found        (Used by VNC)")
	else:
		print("Port 5800      Not Found    (Used by VNC)")
	if 5900 in UNIQE_NET_PORT:
		print("Port 5900      Found        (Used by VNC)")
	else:
		print("Port 5900      Not Found    (Used by VNC)")
	if 5938 in UNIQE_NET_PORT:
		print("Port 5938      Found        (Used by TeamViewer)")
	else:
		print("Port 5938      Not Found    (Used by TeamViewer)")
	if 6568 in UNIQE_NET_PORT:
		print("Port 6568      Found        (Used by Anydesk Client)")
	else:
		print("Port 6568      Not Found    (Used by Anydesk Client)")
	if 7171 in UNIQE_NET_PORT:
		print("Port 7171      Found        (Used by Devolutions Remote Desktop Manager)")
	else:
		print("Port 7171      Not Found    (Used by Devolutions Remote Desktop Manager)")
	if 8008 in UNIQE_NET_PORT:
		print("Port 8008      Found        (Used by Smart TV, Chromecasts and Google Home)")
	else:
		print("Port 8008      Not Found    (Used by Smart TV, Chromecasts and Google Home)")
	if 8009 in UNIQE_NET_PORT:
		print("Port 8009      Found        (Used by Smart TV, Chromecasts and Google Home)")
	else:
		print("Port 8009      Not Found    (Used by Smart TV, Chromecasts and Google Home)")
	if 8040 in UNIQE_NET_PORT:
		print("Port 8040      Found        (Used by ConnectWise Control)")
	else:
		print("Port 8040      Not Found    (Used by ConnectWise Control)")
	if 8080 in UNIQE_NET_PORT:
		print("Port 8080      Found        (Used by HTTP Web Proxy)")
	else:
		print("Port 8080      Not Found    (Used by HTTP Web Proxy)")
	if 8443 in UNIQE_NET_PORT:
		print("Port 8443      Found        (Used by Smart TV, Chromecasts and Google Home)")
	else:
		print("Port 8443      Not Found    (Used by Smart TV, Chromecasts and Google Home)")
	if 9000 in UNIQE_NET_PORT:
		print("Port 9000      Found        (Used by Buffalo TeraStation NAS Drives)")
	else:
		print("Port 9000      Not Found    (Used by Buffalo TeraStation NAS Drives)")
	if 9200 in UNIQE_NET_PORT:
		print("Port 9200      Found        (Used by ElasticSearch)")
	else:
		print("Port 9200      Not Found    (Used by ElasticSearch)")
	if 10001 in UNIQE_NET_PORT:
		print("Port 10001     Found        (Used by Gas Station Pump Controllers)")
	else:
		print("Port 10001     Not Found    (Used by Gas Station Pump Controllers)")
	if 11211 in UNIQE_NET_PORT:
		print("Port 11211     Found        (Port for Memcached, Used in DDoS Attack)")
	else:
		print("Port 11211     Not Found    (Port for Memcached, Used in DDoS Attack)")
	if 12581 in UNIQE_NET_PORT:
		print("Port 12581     Found        (Used by Siemens HVAC Controllers)")
	else:
		print("Port 12581     Not Found    (Used by Siemens HVAC Controllers)")
	if 16992 in UNIQE_NET_PORT:
		print("Port 16992     Found        (Used for Remote Access by Intel Active Management)")
	else:
		print("Port 16992     Not Found    (Used for Remote Access by Intel Active Management)")
	if 16993 in UNIQE_NET_PORT:
		print("Port 16993     Found        (Used for Remote Access by Intel Active Management)")
	else:
		print("Port 16993     Not Found    (Used for Remote Access by Intel Active Management)")
	if 16994 in UNIQE_NET_PORT:
		print("Port 16994     Found        (Used for Remote Access by Intel Active Management)")
	else:
		print("Port 16994     Not Found    (Used for Remote Access by Intel Active Management)")
	if 16995 in UNIQE_NET_PORT:
		print("Port 16995     Found        (Used for Remote Access by Intel Active Management)")
	else:
		print("Port 16995     Not Found    (Used for Remote Access by Intel Active Management)")
	if 25565 in UNIQE_NET_PORT:
		print("Port 25565     Found        (Used by Minecraft Servers)")
	else:
		print("Port 25565     Not Found    (Used by Minecraft Servers)")
	if 27017 in UNIQE_NET_PORT:
		print("Port 27017     Found        (Used by MongoDB Database)")
	else:
		print("Port 27017     Not Found    (Used by MongoDB Database)")
	if 32400 in UNIQE_NET_PORT:
		print("Port 32400     Found        (Used by Plex Device or Server)")
	else:
		print("Port 32400     Not Found    (Used by Plex Device or Server)")

print("\n\n")