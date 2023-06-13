![](https://komarev.com/ghpvc/?username=mamun-sec&color=blue&label=Total+Recent+Views) ![status](https://img.shields.io/badge/status-up-brightgreen)<br>
<code><a href="https://www.linkedin.com/in/mamun-infosec/">Linkedin</a></code> <code><a href="mailto:ceo@intarna.com">Email</a></code> <code><a href="https://medium.com/@alfalahum">Blog</a></code> <code><a href="https://medium.com/@alfalahum">Medium</a></code>

<h1>:white_square_button: Decap</h1>
<h4>Scan PCAP Files for Security Issues</h4>
Analyzing PCAP file in forensic investigation or, incident response takes a long time. In such cases, Decap tool will help you to initially scan the PCAP file.

<br>
<h3>:ledger: Feature</h3>
<ul>
  <li>Get the security reputation of IP address.</li>
  <li>Get the security reputation of URL.</li>
  <li>Get MAC address and vendor name.</li>
  <li>Check existence of suspicious network ports.</li>
</ul>

<br>
<h3>:beginner: Requirements</h3>
<ul>
  <li>Decap tool requires the Internet connection.</li>
  <li>Decap tool is built with PowerShell and Python. If you are using Decap tool for the first time then, install some required Python modules by running the below commands:<br><code>pip install scapy</code><br><code>pip install OTXv2</code></li>
</ul>

<br>
<h3>:black_square_button: How to Run</h3>
<ul>
  <li>Open up the Command Prompt (cmd.exe) and go to the Decap tool's folder. For example, if your Decap folder location is 'E:\Downloads\decap-main' then run the below command:<br><code>cd E:\Downloads\decap-main</code></li>
</ul>

<ul>
  <li>Now use the below command to run the Decap tool:<br><code>powershell -File decap.ps1 file.pcap</code><br><br>Replace file.pcap with your PCAP file location. For example, if you want to scan the 'E:\Packets\file.pcap' file then run the below command:<br><code>powershell -File decap.ps1 E:\Packets\file.pcap</code></li>
</ul>

<br>
<h3>:toolbox: Don't have PCAP file?</h3>
<ul>
  <li>You can download PCAP files of malware infected network from <a href="https://www.malware-traffic-analysis.net/training-exercises.html">Malware Traffic Analysis</a>. Password of the ZIP file will be <code>infected</code>.</li>
  <li>You can also download from <a href="https://www.netresec.com/?page=PcapFiles">Netresec</a>.</li>
</ul>
