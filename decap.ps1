param(
    [Parameter(Mandatory)]
    [String]$FILE_NAME
)

#############
# Show Banner
#############
& .\Scripts\banner.ps1


##################################
# Check Existence of File Location
##################################
$FILE_EXISTS = Test-Path -Path $FILE_NAME -PathType Leaf
if(-Not $FILE_EXISTS) {
    Write-Host ""
    Write-Host -ForegroundColor White -BackgroundColor Red "Error: The PCAP File Does Not Exist"
    Write-Host ""
    Exit
}



###########
# Variables
###########
$TEMP_FILE = ".\Scripts\fileName.txt"
$PCAP_IP_INFO = ".\Scripts\ipinfo.py"
$PCAP_URL_INFO = ".\Scripts\urlinfo.py"
$PCAP_MAC_INFO = ".\Scripts\macinfo.py"
$PCAP_PORT_INFO = ".\Scripts\portinfo.py"
$PCAP_PORT_SCAN = ".\Scripts\portscan.py"
$DECAP_FINAL = ".\Scripts\final.py"


##############################################
# Write PCAP File Location to A Temporary File
##############################################
Add-Content -Path $TEMP_FILE -Value ""
Clear-Content -Path $TEMP_FILE
Add-Content -Path $TEMP_FILE -Value $FILE_NAME


#########################################
# Get IP Address Information of PCAP File
#########################################
Write-Host -ForegroundColor Black -BackgroundColor White "IPv4 Address Scan"
Write-Host ""
python $PCAP_IP_INFO


##################################
# Get URL Information of PCAP File
##################################
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host -ForegroundColor Black -BackgroundColor White "HTTP URL Scan"
Write-Host ""
python $PCAP_URL_INFO


##########################################
# Get MAC Address Information of PCAP File
##########################################
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host -ForegroundColor Black -BackgroundColor White "Device MAC Address And Vendor Name"
Write-Host ""
python $PCAP_MAC_INFO


###########################################
# Get Network Port Information of PCAP File
###########################################
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host -ForegroundColor Black -BackgroundColor White "Network Port List"
Write-Host ""
python $PCAP_PORT_INFO


###############################################
# Scan Network Port for Suspicious Network Port
###############################################
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host -ForegroundColor Black -BackgroundColor White "Suspicious Network Port"
Write-Host ""
python $PCAP_PORT_SCAN


#####################
# Completing The Scan
#####################
Write-Host ""
Write-Host ""
Write-Host -ForegroundColor Black -BackgroundColor White "Scan Complete"
python $DECAP_FINAL