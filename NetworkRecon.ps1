function Invoke-TraceCollect
{
<#
.SYNOPSIS

This module performs a network trace using PowerShell network tracing functionality.
After the trace is complete, the module will perform analysis based on user provided
arguments to determin whether potentially vulnerable traffic exists in the targeted 
trace. 

Function: Invoke-TraceCollect
Author: David Fletcher
License: BSD 3-Clause
Required Dependencies: User must be administrator to capture traffic.
Optional Dependencies: None

.DESCRIPTION

This module performs a network trace using PowerShell network tracing functionality.
After the trace is complete, the module will perform analysis based on user provided
arguments to determin whether potentially vulnerable traffic exists in the targeted 
trace. 

.PARAMETER Duration

This parameter is optional and will specify the duration, in minutes, that traffic
will be collected before analysis is performed. If no value is specified, then the 
network trace will run for 5 minutes by default.

.PARAMETER Folder

This parameter is optional and will specify the folder where the packet capture will be
stored. This is useful if the user wants to export and convert the resulting event trace
file to .pcap format using Microsoft Message Analyzer. If no value is specified, then the 
script will use the folder C:\temp

.PARAMETER File

This parameter is optional and will specify the file name used for the stored event trace log.
If no value is specified, then the file will be named capture_[DateTime.ToString()].etl.

.PARAMETER Size

This parameter is optional and will specify the maximum size of the capture file. If no value
is specified, then the system default will be used. This is usually 250 MB.

.EXAMPLE

C:\PS> Invoke-TraceCollect

Description
-----------
This invocation will execute a network event trace with default arguments (collect for 5 minutes, store the trace
at C:\temp\capture_[DateTime.ToString()].etl, and perform all checks.

.EXAMPLE

C:\PS> Invoke-TraceCollect -Folder "C:\Users\Test" -File "capture.etl" -Duration 10

Description
-----------
This invocation will execute a network event trace for 10 minutes saving the output to "C:\Users\Test\capture.etl"
and perform allchecks

#>
Param(
 [Parameter(Position = 0, Mandatory = $false)]
 [string]
 $Folder = "C:\temp",

 [Parameter(Position = 1, Mandatory = $false)]
 [string]
 $Name = ("capture_" + (Get-Date).Year + (Get-Date).Month + (Get-Date).Day + (Get-Date).Hour + (Get-Date).Minute + (Get-Date).Second),

 [Parameter(Position = 2, Mandatory = $false)]
 [int]
 $Duration = 5,

 [Parameter(Position = 3, Mandatory = $false)]
 [int]
 $Size = 250

)
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "Administrator rights are required in order to execute trace collection.`nThis function uses standard Windows conventions which requires elevation."
    Break
}

# Check to see if the target folder exists
If ((Test-Path $folder) -eq $false)
{
    Write-Host "[+] Target folder does not exist, creating it"
    $createFolder = ("cmd.exe /C mkdir " + $folder)
    Invoke-Expression $createFolder
}
else
{
    Write-Host "[+] Target folder exists, no action required"
}

# Set the path to the output file
$seconds = $Duration * 60

# Start the session to begin collecting packets
Write-Host "[+] Starting capture session"

# Try running a PEF trace first.  If the PEF module is available it is capable
# of generating a cap file which can be consumed and analyzed with Wireshark.
# The PEF modules are only available with Windows 8 and above. If this fails
# then we fall back to running netsh trace to capture packet data using the Windows
# NDIS provider.
try 
{
    Write-Host "   [-] Trying PEF trace first..."
    Import-Module PEF
    # We're using PEF so we can generate a cap file instead of etl
    $Path= ($Folder + "\" + $Name + ".cap")
    # Set up the session using the provided parameters. I have not found a way to specify
    # the maximum trace size, so the default of 250 MB is used. This should be plenty of 
    # storage space for the resulting file.
    $session = New-PefTraceSession -Name $Name -Path $Path -SaveOnStop Linear -Force
    # Add the NDIS-PacketCapture provider to the session
    Add-PefMessageProvider -PEFSession $session -Provider "Microsoft-Windows-NDIS-PacketCapture" > $null
    # TODO: Windows 10 Supports promiscuous mode by using Add-NetEventNetworkAdapter commandlet.
    # Add support for this commandlet to ensure we are getting everything.
    # Create a TimeSpanTrigger to stop the capture.  Once the capture starts we lose interactive control
    $trigger = New-PefTimeSpanTrigger -TimeSpan (New-TimeSpan -Seconds $seconds)
    # Output status messages to the user
    Write-Host "   [-] Successfully created PEF Trace Session..."
    Write-Host ("   [-] Output will be saved to " + $Path)
    Write-Host ("   [-] Trace will execute for " + $Duration + " minutes while packet capture is running")
    # Assign the trigger event to the Stop-PefTraceSession commandlet
    Stop-PefTraceSession -PEFSession $session -Trigger $trigger > $null
    # Start the session. When the specified time has elapsed, the trace will stop
    Start-PefTraceSession -PEFSession $session > $null
    Write-Host "   [-] Session stopped"    
    Write-Host "[+] Packet capture complete"
}
catch
{
    Write-Host "   [!] Unable to create PEF trace...falling back to netsh..."
    $Path= ($Folder + "\" + $Name + ".etl")
    Write-Host "   [-] Output will be saved to " $Path
    $traceCommand = ("netsh trace start provider=Microsoft-Windows-NDIS-PacketCapture tracefile=" + $Path + " maxSize=" + $Size + " capture=yes overwrite=yes filemode=single")
    Invoke-Expression $traceCommand


    Write-Host ("   [-] Sleeping for " + $Duration + " minutes while packet capture is running")
    Start-Sleep -s $seconds

    # Stop the session to cease packet collection
    Write-Host "[+] Packet capture complete"
    Write-Host "   [-] Stopping capture session"
    netsh trace stop
}

}

function Invoke-NeighborCacheAnalysis
{
<#
.SYNOPSIS

This module performs a check of the layer 2 cache on the local computer to determine 
whether addresses of interest are cached. Given the frequency with which the 
interesting protocols communicate, it is likely that the presence of these cached
entries identify that the host is able to observe these potentially vulnerable protocols.
 

Function: Invoke-NeighborCacheAnalysis
Author: David Fletcher
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

This module performs a check of the layer 2 cache on the local computer to determine 
whether addresses of interest are cached. Given the frequency with which the 
interesting protocols communicate, it is likely that the presence of these cached
entries identify that the host is able to observe these potentially vulnerable protocols.

LLMNR could be a false-positive since it appears to be a static entry present on all Windows hosts.


.EXAMPLE

C:\PS> Invoke-NeighborCacheAnalysis

Description
-----------
This invocation will inspect the layer 2 cache of each of the connected network adapters and 
identify whether multicast addresses for a given protocol are present.  If so, the output
reports the presence of the protocol and which OSI layer it was observed at.

#>
Param(
)

# Get the list of connected network adapters
# Ge-NetAdapter doesn't work in Windows 7
# See if we support Get-NetAdapter, if not, we have to use 
# netsh output and parse results
$parseOld = $false
try
{
    $adapters = Get-NetAdapter
    $parseOld = $false
}
catch
{
   $adapters = Get-ParsedAdapterNames
   $parseOld = $true
}

    foreach ($adapter in $adapters)
    {
        if ($parseOld -eq $true)
        {
            $neighbors = Get-ParsedArpTables -InterfaceIndex $adapter.Name
        }
        else
        {
            $neighbors = Get-NetNeighbor -InterfaceAlias $adapter.Name 
        }

        Write-Host ("[+] Checking Neighbor Entries for Known Protocol Addresses (" + $adapter.Name + ")")
        foreach ($neighbor in $neighbors)
        {
            # Check for Known Ethernet Multicast Adddresses to Determine Potential Exposed Protocols
            switch ($neighbor.LinkLayerAddress)
            {
                # Check for the CDP/VTP Multicast Address
                "01000ccccccc"
                {
                    Write-Host "   [-] Layer 2 CDP/VTP Address Found in Neighbor Cache"
                }
                # Check for the STP Multicast Address
                "0180c2000000"
                {
                    Write-Host "   [-] Layer 2 STP Address Found in Neighbor Cache"
                }
                # Check for the LLDP Multicast Addresses
                "0180c2000000"
                {
                    Write-Host "   [-] Layer 2 LLDP Address Found in Neighbor Cache"
                }
                "0180c2000003"
                {
                    Write-Host "   [-] Layer 2 LLDP Address Found in Neighbor Cache"
                }
                "0180c200000E"
                {
                    Write-Host "   [-] Layer 2 LLDP Address Found in Neighbor Cache"
                }
                # Check this one, it is listed as "All Routers" multicast group
                "01005e000002"
                {
                    Write-Host "   [-] Layer 2 HSRP Address Found in Neighbor Cache"
                }
                # Check for the OSPF HELLO Multicast Address
                "01005e000005"
                {
                    Write-Host "   [-] Layer 2 OSPF HELLO Address Found in Neighbor Cache"
                }
                "333300000005"
                {
                    Write-Host "   [-] Layer 2 OSPF HELLO Address Found in Neighbor Cache"
                }
                # Check for the OSPF DR Multicast Address
                "01005e000006"
                {
                    Write-Host "   [-] Layer 2 OSFP DR Address Found in Neighbor Cache"
                }
                "333300000006"
                {
                    Write-Host "   [-] Layer 2 OSPF DR Address Found in Neighbor Cache"
                }
                # Check for the VRRP Multicast Address
                "01005e000012"
                {
                    Write-Host "   [-] Layer 2 VRRP Address Found in Neighbor Cache"
                }
                # Check for the mDNS Multicast Address
                "01005e0000fb"
                {
                    Write-Host "   [-] Layer 2 mDNS Address Found in Neighbor Cache"
                }
                "3333000000fb"
                {
                    Write-Host "   [-] Layer 2 mDNS Address Found in Neighbor Cache"
                }
                # Check for the LLMNR Multicast Address
                "01005e0000fc"
                {
                    Write-Host "   [-] Layer 2 LLMNR Address Found in Neighbor Cache"
                }
                "333300000103"
                {
                    Write-Host "   [-] Layer 2 LLMNR Address Found in Neighbor Cache"
                }
            }
            # Check IP Addresses for Known IP Multicast
            switch ($neighbor.IPAddress)
            {
                # Check for the IPv4 HSRP Multicast Address
                "224.0.0.2"
                {
                    Write-Host "   [-] IPv4 HSRP Address Found in Neighbor Cache"
                }
                # Check for the IPv4 OSPF HELLO Multicast Address
                "224.0.0.5"
                {
                    Write-Host "   [-] IPv4 OSPF HELLO Address Found in Neighbor Cache"
                }
                # Check for the IPv4 OSPF DR Multicast Address
                "224.0.0.6"
                {
                    Write-Host "   [-] IPv4 OSFP DR Address Found in Neighbor Cache"
                }
                # Check for the IPv4 VRRP Multicast Address
                "224.0.0.18"
                {
                    Write-Host "   [-] IPv4 VRRP Address Found in Neighbor Cache"
                }
                # Check for the IPv4 HSRP v3 Multicast Address
                "224.0.0.102"
                {
                    Write-Host "   [-] IPv4 HSRPv3 Address Found in Neighbor Cache"
                }
                # Check for the IPv4 mDNS Multicast Address
                "224.0.0.251"
                {
                    Write-Host "   [-] IPv4 mDNS Address Found in Neighbor Cache"
                }
                # Check for the IPv4 LLMNR Multicast Address
                "224.0.0.252"
                {
                    Write-Host "   [-] IPv4 LLMNR Address Found in Neighbor Cache"
                }
                # Check for the IPv6 OSPF HELLO Multicast Address
                "ff02::5"
                {
                    Write-Host "   [-] IPv6 OSPF HELLO Address Found in Neighbor Cache"
                }
                # Check for the IPv6 OSPF DR Multicast Address
                "ff02::6"
                {
                    Write-Host "   [-] IPv6 OSFP DR Address Found in Neighbor Cache"
                }
                # Check for the IPv6 OSPF DR Multicast Address
                "ff02::12"
                {
                    Write-Host "   [-] IPv6 VRRP Address Found in Neighbor Cache"
                }
                # Check for the IPv6 VRRP Multicast Address
                "ff02::66"
                {
                    Write-Host "   [-] IPv6 HSRPv3 Address Found in Neighbor Cache"
                }
                # Check for the IPv6 LLMNR Multicast Address
                "ff02::1:3"
                {
                    Write-Host "   [-] IPv6 LLMNR Address Found in Neighbor Cache"
                }
                # Check for the IPv6 mDNS Multicast Address
                "ff02::fb"
                {
                    Write-Host "   [-] IPv6 mDNS Address Found in Neighbor Cache"
                }   
            }
        }
    }
}

function Get-ParsedAdapterNames
{
<#
.SYNOPSIS

This module simulates the behavior of the Get-NetNeighbor commandlet available
in Windows 8 and above. It does not return NetNeighbor objects. Only the information
(MAC and IP address) returned from the netsh commands that are used within the 
functionality of the exposed commandlets in this package. 

Function: Get-ParsedArpTables
Author: David Fletcher
License: BSD 3-Clause
Required Dependencies: User must be administrator to capture traffic.
Optional Dependencies: None

.DESCRIPTION

This module returns the MAC and IP addresses found within the output of the 
following commands:

netsh int ipv4 show neigh interface=$InterfaceIndex
netsh int ipv6 show neigh interface=$InterfaceIndex

The results are returned in a PowerShell cusom object having the properties LinkLayerAddress
and IPAddress which conforms with the results returned by Get-NetNeighbor.

.PARAMETER InterfaceIndex

This parameter is mandatory and identifies the interface for which arp table entries are being parsed.
This can be the integer interface index or the string interface name. The latter is generated by the 
Get-ParsedAdapterNames function.

#>
    $cmdOutput = netsh int show int
    foreach ($line in $cmdOutput)
    {
        if (($line.Trim() -eq '') -or $line.Contains('Admin State') -or $line.Contains('---'))
        {
            # The first line in the output is null, so skip it
            # The second line in the output is the table header, so skip it
            continue
        }
        else
        {
            $elements = ($line -replace " {2,}"," ").Split(' ')
            $adapter = @{}
            $adapter.Name = $elements[3]
            Write-Output $adapter
        }
    }
}

function Get-ParsedArpTables
{
<#
.SYNOPSIS

This module simulates the behavior of the Get-NetNeighbor commandlet available
in Windows 8 and above. It does not return NetNeighbor objects. Only the information
(MAC and IP address) returned from the netsh commands that are used within the 
functionality of the exposed commandlets in this package. 

Function: Get-ParsedArpTables
Author: David Fletcher
License: BSD 3-Clause
Required Dependencies: User must be administrator to capture traffic.
Optional Dependencies: None

.DESCRIPTION

This module returns the MAC and IP addresses found within the output of the 
following commands:

netsh int ipv4 show neigh interface=$InterfaceIndex
netsh int ipv6 show neigh interface=$InterfaceIndex

The results are returned in a PowerShell cusom object having the properties LinkLayerAddress
and IPAddress which conforms with the results returned by Get-NetNeighbor.

.PARAMETER InterfaceIndex

This parameter is mandatory and identifies the interface for which arp table entries are being parsed.
This can be the integer interface index or the string interface name. The latter is generated by the 
Get-ParsedAdapterNames function.

#>
Param(
 [Parameter(Position = 0, Mandatory = $true)]
 [string]
 $InterfaceIndex
)
    # Array of netsh commands to retrieve the arp cache entries for the local computer
    $commands = ("netsh int ipv4 show neigh interface=" + $InterfaceIndex),("netsh int ipv6 show neigh interface=" + $InterfaceIndex)
    
    # Process each command and process the resulting output
    foreach ($command in $commands)
    {
        # Exectute the command expression and save the results
        $cmdOutput = Invoke-Expression $command

        # Process each line of output
        foreach ($line in $cmdOutput)
        {
            # Throw away unnecessary header information
            if (($line.Trim() -eq '') -or $line.Contains('Internet Address') -or $line.Contains('---') -or $line.Contains($InterfaceIndex))
            {
                # The first line in the output is null, so skip it
                # The second line in the output is the table header, so skip it
                continue
            }
            else
            {
                # This output is space delimited but the space count is asymmetric so we need to normalize the input
                # Here we are replacing 2 or more spaces with a single space then splitting the result on the single space 
                $elements = ($line -replace " {2,}"," ").Split(' ')

                # Create our output object to place on the pipeline
                $neighbor = @{}
                $neighbor.IPAddress = $elements[0]
                # Change the format of the MAC address to match the output of Get-NetNeighbor
                $neighbor.LinkLayerAddress = $elements[1].Replace('-','').ToLower()

                # Write the output to the pipeline
                Write-Output $neighbor
            }
        }
    }
}

function Invoke-LiveAnalysis
{
<#
.SYNOPSIS

This module performs a network trace using PowerShell network tracing functionality.
After the trace is complete, the module will perform analysis based on user provided
arguments to determin whether potentially vulnerable traffic exists in the targeted 
trace. 

This module performs live analysis of network traffic observable by the host computer. This
module can be used to confirm or augment the results returned by Invoke-NeighborCacheAnalysis.
Unlike, Invoke-NeighborCacheAnalysis, this module will detect DHCP and NBNS traffic and can parse 
details from other protocols but cannot identify cdp/dtp/vtp or other layer 2 only protocols.

This module borrows heavily from the sniffer module implemented in the Invoke-Inveigh module but 
currently uses this functionality to implement identify and parse capabilities. Future enhancements
may include the ability to attack the network through information disclosure, route manipulation,
malicious boot and other attacks currently provided by tools that are predominately linux.

Function: Invoke-LiveAnalysis
Author: David Fletcher
License: BSD 3-Clause
Required Dependencies: User must be administrator to capture traffic.
Optional Dependencies: None

.DESCRIPTION

This module performs live analysis of network traffic observable by the host computer. This
module can be used to confirm or augment the results returned by Invoke-NeighborCacheAnalysis.
Unlike, Invoke-NeighborCacheAnalysis, this module will detect DHCP and NBNS traffic and can parse 
details from other protocols but cannot identify cdp/dtp/vtp or other layer 2 only protocols.

.EXAMPLE

C:\PS> Invoke-LiveAnalysis

Description
-----------
This invocation will execute live network analysis with all default parameters (console output provided, no log file, infinite duration).

#>
Param(
)

# Check to see if we're running as administrator. Alert and note if we aren't,
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”))
{
    Write-Warning "Script IS NOT running as administrator."
    $admin = $false
}
else
{
    Write-Host "Script IS running as administrator."
    $admin = $true
}

# Get the IP Address of the network interface
# This may need to be changed to support a computer with multiple interfaces

if(!$IP)
{ 
    $IP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
}

if(!$analyzer)
{
    $global:analyzer = [HashTable]::Synchronized(@{})
    $analyzer.console_queue = New-Object System.Collections.ArrayList
    $analyzer.show_dhcp = $true
    $analyzer.show_hsrp = $true
    $analyzer.show_llmnr = $true
    $analyzer.show_mdns = $true
    $analyzer.show_nbns = $true
    $analyzer.show_ospf = $true
    $analyzer.show_vrrp = $true
    $analyzer.rule_name = "Multicast Inbound Allow"
}

$analyzer.sniffer_socket = $null
$analyzer.running = $true

$analyzer.console_queue.Add("Analyzer started at $(Get-Date -format 's')")  > $null

$firewall_status = netsh advfirewall show allprofiles state | Where-Object {$_ -match 'ON'}

if($firewall_status)
{
    $analyzer.console_queue.Add("Windows Firewall = Enabled")  > $null
    $firewall_rules = New-Object -comObject HNetCfg.FwPolicy2
    $firewall_powershell = $firewall_rules.rules | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq 1} |Select-Object -Property Name | Select-String "Windows PowerShell}"

    if($firewall_powershell)
    {
        $analyzer.console_queue.Add("Windows Firewall - PowerShell.exe = Allowed")  > $null
    }

    # The Windows firewall does not allow inbound multicast packets by default. As a result, if the firewall
    # is enabled we won't be able to check for some of the interesting protocols. Therefore, we can either 
    # attempt to disable the firewall using
    # netsh advfirewall set allprofiles state off < This increases our exposure to attack. We only want to see inbound traffic
    # a better option is to allow the multicast addresses we're interested in inbound
    # netsh advfirewall firewall add rule name="Multicast Inbound Allow" dir=in action=allow localip="224.0.0.0/24"
    if ($admin)
    {
        $analyzer.console_queue.Add("Inserted Inbound Multicast Rule") > $null
        $rule = "cmd.exe /C netsh advfirewall firewall add rule name=`"Multicast Inbound Allow`" dir=in action=allow localip=`"224.0.0.0/24`""
        Invoke-Expression $rule > $null
    }
}

$analyzer.console_queue.Add("Listening IP Address = $IP")  > $null

# Begin ScriptBlocks

# Shared Basic Functions ScriptBlock
$shared_basic_functions_scriptblock =
{

    function DataToUInt16($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt16($field,0)
    }

    function DataToUInt32($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt32($field,0)
    }

    function DataLength2
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)
        return $string_length
    }

    function DataLength4
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToUInt32($string_extract_data[$length_start..($length_start + 3)],0)
        return $string_length
    }

    function DataToString
    {
        param ([Int]$string_start,[Int]$string_length,[Byte[]]$string_extract_data)

        $string_data = [System.BitConverter]::ToString($string_extract_data[$string_start..($string_start + $string_length - 1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
        return $string_extract
    }
    function DataToHexString
    {
        param ([Int]$string_start,[Int]$string_length,[Byte[]]$string_extract_data)

        $string_data = [System.BitConverter]::ToString($string_extract_data[$string_start..($string_start + $string_length - 1)])
        $string_data = $string_data -replace "-",""
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
        return $string_extract.ToLower()
    }

}

$sniffer_scriptblock = 
{
    param ($IP,$RunTime)

    $byte_in = New-Object System.Byte[] 4	
    $byte_out = New-Object System.Byte[] 4	
    $byte_data = New-Object System.Byte[] 4096
    $byte_in[0] = 1
    $byte_in[1-3] = 0
    $byte_out[0] = 1
    $byte_out[1-3] = 0
    $analyzer.sniffer_socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    $analyzer.sniffer_socket.SetSocketOption("IP","HeaderIncluded",$true)
    $analyzer.sniffer_socket.ReceiveBufferSize = 1024
    $end_point = New-Object System.Net.IPEndpoint([System.Net.IPAddress]"$IP",0)
    $analyzer.sniffer_socket.Bind($end_point)
    $analyzer.sniffer_socket.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll,$byte_in,$byte_out)

    while($analyzer.running)
    {
        # Inveigh sniffer is only configured to parse IPv4 Packets
        $packet_data = $analyzer.sniffer_socket.Receive($byte_data,0,$byte_data.Length,[System.Net.Sockets.SocketFlags]::None)
        $memory_stream = New-Object System.IO.MemoryStream($byte_data,0,$packet_data)
        $binary_reader = New-Object System.IO.BinaryReader($memory_stream)
        $version_more = $binary_reader.ReadByte()
        $IP_version = [Int]"0x$(('{0:X}' -f $version_more)[0])"


        if ($IP_version -eq 4)
        {
            # Process the IPv4 Header
            $header_length = [Int]"0x$(('{0:X}' -f $version_more)[1])" * 4
            $type_of_service= $binary_reader.ReadByte()
            $total_length = DataToUInt16 $binary_reader.ReadBytes(2)
            $identification = $binary_reader.ReadBytes(2)
            $flags_offset = $binary_reader.ReadBytes(2)
            $TTL = $binary_reader.ReadByte()
            $protocol_number = $binary_reader.ReadByte()
            $header_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
            $source_IP_bytes = $binary_reader.ReadBytes(4)
            $source_IP = [System.Net.IPAddress]$source_IP_bytes
            $destination_IP_bytes = $binary_reader.ReadBytes(4)
            $destination_IP = [System.Net.IPAddress]$destination_IP_bytes
         }
         elseif ($IP_version -eq 6)
         {
            # Process the IPv6 Header
            # Intially, we won't process traffic class and flow label
            # since they aren't needed for analysis
            $traffic_high = 0 # Get low order nibble from $version_more
            $traffic_flow = $binary_reader.ReadBytes(3)
            $traffic_low = 0 # Get high order nibble from $traffic_flow
            $flow_label = 0 # Zero out 4 high order bits from $traffic_flow
            $total_length = DataToUInt16 $binary_reader.ReadBytes(2)
            # This is next header but we may not need to do anything with this 
            # depending on whether additional headers are typically seen in the
            # protocols we are interested in. May be useful to report this value 
            # for debugging purposes. If the protocols of interest have several 
            # extension headers, it may be useful to have a function dedicated to 
            # IPv6 next header chain walking to deteremine if one of the interesting 
            # protocols is present. Will test with IPv6.
            $protocol_number= $binary_reader.ReadByte()
            $TTL = $binary_Reader.ReadByte()
            $source_IP_bytes = $binary_reader.ReadBytes(16)
            $source_IP = [System.Net.IPAddress]$source_IP_bytes
            $destination_IP_bytes = $binary_reader.ReadBytes(16)
            $destination_IP = [System.Net.IPAddress]$destination_IP_bytes
         }
         else
         {
            continue
         }

        # Packet processing starts here. The flow consists of inspecting the embedded protocol number first
        # OSPF and VRRP do not use standard protocol numbers (TCP and UDP). Then we will inspect the specific protocol further
        switch ($protocol_number)
        {
            # TCP Processing
            6
            {
                $source_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $sequence_number = DataToUInt32 $binary_reader.ReadBytes(4)
                $ack_number = DataToUInt32 $binary_reader.ReadBytes(12)
                $TCP_header_length = [Int]"0x$(('{0:X}' -f $binary_reader.ReadByte())[0])" * 4
                $TCP_flags = $binary_reader.ReadByte()
                $TCP_window = DataToUInt16 $binary_reader.ReadBytes(2)
                $TCP_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
                $TCP_urgent_pointer = DataToUInt16 $binary_reader.ReadBytes(2)    
                $payload_bytes = $binary_reader.ReadBytes($total_length - ($header_length + $TCP_header_length))

            }
            # UDP Processing
            17
            {
                $source_port = $binary_reader.ReadBytes(2)
                $endpoint_source_port = DataToUInt16 ($source_port)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $UDP_length = $binary_reader.ReadBytes(2)
                $UDP_length_uint  = DataToUInt16 ($UDP_length)
                $binary_reader.ReadBytes(2)

                switch ($destination_port)
                {
                    # DHCP Packet/Options Inspection
                    68
                    {
                        if ($analyzer.show_dhcp)
                        {
                            $dhcp_opcode = $binary_reader.ReadByte()

                            # We are only interested in DHCP Responses which may contain
                            # a boot file location which we may be able to use for boot
                            # image analysis or malicious boot attack
                            if ($dhcp_opcode -eq 2)
                            {
                                $analyzer.console_queue.Add("DHCP response received from " + $source_IP.ToString()) > $null

                                # Parse the remainder of the packet
                                $dhcp_hwtype = $binary_reader.ReadByte()
                                $dhcp_hwaddlength = $binary_reader.ReadByte()
                                $dhcp_hopcount = $binary_reader.ReadByte()
                                $dhcp_trans_id_bytes = $binary_reader.ReadBytes(4)
                                $dhcp_trans_id = DataToUInt32 $dhcp_trans_id_bytes
                                $dhcp_lease_duration = DataToUInt16 $binary_reader.ReadBytes(2)
                                $dhcp_flags = DataToUInt16 $binary_reader.ReadBytes(2)
                                $dhcp_client_ip_bytes = $binary_Reader.ReadBytes(4)
                                $dhcp_sender_ip_bytes = $binary_reader.ReadBytes(4)
                                $dhcp_server_ip_bytes = $binary_reader.ReadBytes(4)
                                $dhcp_server_ip = [System.Net.IPAddress] $dhcp_server_ip_bytes
                                $dhcp_gateway_ip_bytes = $binary_reader.ReadBytes(4)
                                $dhcp_client_hw_addr_bytes = $binary_reader.ReadBytes(6)
                                $dhcp_client_hw_addr_padding = $binary_reader.ReadBytes(10)
                                $dhcp_server_hostname_bytes = $binary_reader.ReadBytes(64)
                                $dhcp_server_hostname_bytes = DataToString $dhcp_server_hostname_bytes
                                $dhcp_server_boot_filename_bytes = $binary_reader.ReadBytes(128)
                                $dhcp_server_boot_filename = DataToString $dhcp_server_boot_filename_bytes

                                if ($dhcp_server_ip.Trim() -ne "")
                                {
                                    $analyzer.console_queue.Add(" [i] DHCP Server IP: " + $dhcp_server_ip) > $null
                                }

                                if ($dhcp_server_hostname.Trim() -ne "")
                                {
                                    $analyzer.console_queue.Add(" [i] DHCP Server Name: " + $dhcp_server_hostname) > $null
                                }

                                if ($dhcp_server_boot_filename.Trim() -ne "")
                                {
                                    $analyzer.console_queue.Add(" [!] Boot File: " + $dhcp_server_boot_filename) > $null
                                    $analyzer.console_queue.Add(" [!] This File Could Contain Credentials") > $null
                                }

                                $dhcp_cookie_bytes = $binary_reader.ReadBytes(4)
                                    
                                # Process DHCP Options
                                $dhcp_option = $binary_reader.ReadByte()
                                
                                # DHCP Option 255 signifies "End Of Options"
                                while ($dhcp_option -ne 255)
                                {
                                    # Process padding bytes
                                    switch ($dhcp_option)
                                    {
                                        # Handle Padding
                                        0
                                        {
                                            $dhcp_option = $binary_reader.ReadByte()
                                            continue
                                        }
                                        # Handle Standard PXE/Network Boot
                                        66
                                        {
                                            $dhcp_option_length = $binary_reader.ReadByte()
                                            $dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
                                            $tftp_server_name = DataToString $dhcp_option_bytes
                                            $analyzer.console_queue.Add(" [!] TFTP Server Name: " + $tftp_server_name) > $null
                                        }
                                        67
                                        {
                                            $dhcp_option_length = $binary_reader.ReadByte()
                                            $dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
                                            $tftp_boot_filename = DataToString $dhcp_option_bytes
                                            $analyzer.console_queue.Add(" [!] TFTP Boot Filename: " + $tftp_boot_filename) > $null
                                            $analyzer.console_queue.Add(" [!] This File Could Contain Credentials") > $null
                                        }
                                        128
                                        {
                                            $dhcp_option_length = $binary_reader.ReadByte()
                                            $dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
                                            $tftp_server_ip = [System.Net.IPAddress]$dhcp_option_bytes
                                            $analyzer.console_queue.Add(" [!] TFTP Server IP: " + $tftp_server_ip) > $null
                                        }
                                        150
                                        {
                                            $dhcp_option_length = $binary_reader.ReadByte()
                                            $dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
                                            $tftp_server_ip = [System.Net.IPAddress]$dhcp_option_bytes
                                            $analyzer.console_queue.Add(" [!] TFTP Server IP: " + $tftp_server_ip) > $null
                                        }
                                        # Handle PXELINUX Requests
                                        208
                                        {
                                            $dhcp_option_length = $binary_reader.ReadByte()
                                            $dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
                                            $analyzer.console_queue.Add(" [!] PXELINUX Magic Option Observed") > $null
                                        }
                                        209
                                        {
                                            $dhcp_option_length = $binary_reader.ReadByte()
                                            $dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
                                            $pxelinux_config = DataToString $dhcp_option_bytes
                                            $analyzer.console_queue.Add(" [!] PXELINUX Config: " + $pxelinux_config) > $null
                                            $analyzer.console_queue.Add(" [!] This File Should Be Inspected") > $null
                                        }
                                        210
                                        {
                                            $dhcp_option_length = $binary_reader.ReadByte()
                                            $dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
                                            $pxelinux_path_prefix = DataToString $dhcp_option_bytes
                                            $analyzer.console_queue.Add(" [!] PXELINUX Prefix: " + $pxelinux_path_prefix) > $null
                                        }
                                        # Handle All Others
                                        default
                                        {
                                            $dhcp_option_length = $binary_reader.ReadByte()
                                            $dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
                                            $analyzer.console_queue.Add(" [i] Observed DHCP Option: " + $dhcp_option.ToString()) > $null
                                            $dhcp_option = $binary_reader.ReadByte()
                                            continue
                                        }
                                    }
                                }
                            }
                        }                        
                    }
                    # NBNS Packet Inspection
                    137
                    {
                        if ($analyzer.show_nbns)
                        {
                            $analyzer.console_queue.Add("NBNS packet received from " + $source_IP.ToString()) > $null
                            $nbns_queryid = DataToUInt16 $binary_reader.ReadBytes(2)
                            $nbns_control = $binary_reader.ReadByte()
                            # split the control field so we can tell if this is query or response
                            $nbns_control_high = [Int]"0x$(('{0:X}' -f $nbns_version_type)[0])"
                            $nbns_control_low = [Int]"0x$(('{0:X}' -f $nbns_version_type)[1])"
                            $nbns_rcode = $binary_reader.ReadByte()
                            $nbns_qdcount = DataToUInt16 $binary_reader.ReadBytes(2)
                            $nbns_ancount = DataToUInt16 $binary_reader.ReadBytes(2)
                            $nbns_nscount = DataToUInt16 $binary_reader.ReadBytes(2)
                            $nbns_arcount = DataToUInt16 $binary_reader.ReadBytes(2)
                                
                            if ($nbns_control_high -lt 8)
                            {
                                $analyzer.console_queue.Add(" [!] Potential for NBNS Poisoning Attack") > $null
                                $analyzer.console_queue.Add(" [i] Type: Query") > $null                
                                $analyzer.console_queue.Add(" [i] Query Count: " + $nbns_qdcount.ToString()) > $null
                                    
                                for ($i = 1; $i -le $nbns_qdcount; $i++)
                                {
                                    $nbns_field_length = $binary_reader.ReadByte()
                                    $nbns_name = ""

                                    while ($nbns_field_length -ne 0)
                                    {
                                        $nbns_field_value_bytes = $binary_reader.ReadBytes($nbns_field_length - 2)
                                        $nbns_query_suffix = [System.BitConverter]::ToString($binary_reader.ReadBytes(2))
                                        # Used NBNS Name decoding code from Inveigh.ps1 below
                                        $nbns_query = [System.BitConverter]::ToString($nbns_field_value_bytes)
                                        $nbns_query = $nbns_query -replace "-00",""
                                        $nbns_query = $nbns_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                        $nbns_query_string_encoded = New-Object System.String ($nbns_query,0,$nbns_query.Length)
                                        $nbns_query_string_encoded = $nbns_query_string_encoded.Substring(0,$nbns_query_string_encoded.IndexOf("CA"))
                                        $nbns_query_string_subtracted = ""
                                        $nbns_query_string = ""
                                        $n = 0
                            
                                        do
                                        {
                                            $nbns_query_string_sub = (([Byte][Char]($nbns_query_string_encoded.Substring($n,1))) - 65)
                                            $nbns_query_string_subtracted += ([System.Convert]::ToString($nbns_query_string_sub,16))
                                            $n += 1
                                        }
                                        until($n -gt ($nbns_query_string_encoded.Length - 1))
                    
                                        $n = 0
                                    
                                        do
                                        {
                                            $nbns_query_string += ([Char]([System.Convert]::ToInt16($nbns_query_string_subtracted.Substring($n,2),16)))
                                        $n += 2
                                        }
                                        until($n -gt ($nbns_query_string_subtracted.Length - 1) -or $nbns_query_string.Length -eq 15)
                                        # Name Conversion is complete
                                            
                                        $nbns_name = $nbns_name + $nbns_query_string
                                            
                                        # Read Next Length for Loop Execution, for NBNS there should only be one record
                                        $nbns_field_length = $binary_reader.ReadByte()
                                            
                                        if ($nbns_field_length -ne 0)
                                        {
                                            $nbns_name = ($nbns_name + ".")
                                        }
                                            
                                        switch ($nbns_query_suffix)
                                        {
                                            '41-41'
                                            {
                                                $nbns_service = "Workstation/Redirector"
                                            }
                                            '41-44'
                                            {
                                                $nbns_service = "Messenger"
                                            }
                                            '43-47'
                                            {
                                                $nbns_service = "Remote Access"
                                            }
                                            '43-41'
                                            {
                                                $nbns_service = "Server"
                                            }
                                            '43-42'
                                            {
                                                $nbns_service = "Remote Access Client"
                                            }
                                            '42-4C'
                                            {
                                                $nbns_service = "Domain Master Browser"
                                            }
                                            '42-4D'
                                            {
                                                $nbns_service = "Domain Controllers"
                                            }
                                            '42-4E'
                                            {
                                                $nbns_service = "Master Browser"
                                            }
                                            '42-4F'
                                            {
                                                $nbns_service = "Browser Election"
                                            }
                                        }                                                
                                    }
                                    
                                    $nbns_record_type = DataToUInt16 $binary_reader.ReadBytes(2)
                                    $nbns_record_class = DataToUInt16 $binary_reader.ReadBytes(2)
                                            
                                    $analyzer.console_queue.Add(" [i] Host: " + $nbns_name) > $null
                                    $analyzer.console_queue.Add(" [i] Service Type: " + $nbns_service) > $null
                                }
                            }
                            else
                            {
                                $analyzer.console_queue.Add(" [i] Type: Response") > $null
                                $analyzer.console_queue.Add(" [i] Response Count: " + $nbns_ancount.ToString()) > $null
                                # May Parse NBNS Responses Further In The Future
                            }
                        }
                    }
                    # HSRP Packet Inspection
                    1985
                    {
                        if ($analyzer.show_hsrp)
                        {
                            # This is for HSRP v0/1. HSRP v2 uses multicast IP 224.0.0.102
                            # HSRP destination should be 224.0.0.2
                            if ($destination_IP.ToString() -eq "224.0.0.2")
                            {
                                $hsrp_version = $binary_reader.ReadByte()
                                $hsrp_opcode = $binary_reader.ReadByte()
                                $hsrp_state = $binary_reader.ReadByte()
                                $hsrp_hellotime = $binary_reader.ReadByte()
                                $hsrp_holdtime = $binary_reader.ReadByte()
                                $hsrp_priority = $binary_reader.ReadByte()
                                $hsrp_group = $binary_reader.ReadByte()
                                $hsrp_reserved = $binary_reader.ReadByte()
                                $hsrp_auth_bytes = $binary_reader.ReadBytes(8)
                                $hsrp_auth = DataToString 0 8 $hsrp_auth_bytes
                                $hsrp_groupip_bytes = $binary_reader.ReadBytes(4)
                                $hsrp_groupip = [System.Net.IPAddress] $hsrp_groupip_bytes
                                    
                                $analyzer.console_queue.Add("HSRP v" + $hsrp_version.ToString() + " Packet Observed from " + $source_IP.ToString()) > $null

                                switch ($hsrp_opcode)
                                {
                                    0
                                    {
                                        $analyzer.console_queue.Add(" [i] Operation: Hello") > $null
                                        $analyzer.console_queue.Add(" [i] Hello Time: " + $hsrp_hellotime.ToString() + " seconds") > $null
                                        $analyzer.console_queue.Add(" [i] Hold Time: " + $hsrp_holdtime.ToString() + " seconds") > $null
                                    }
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [i] Operation: Coup") > $null
                                    }
                                    2
                                    {
                                        $analyzer.console_queue.Add(" [i] Operation: Resign") > $null
                                    }
                                }
                                    
                                switch ($hsrp_state)
                                {
                                    0
                                    {
                                        $analyzer.console_queue.Add(" [i] State: Initial") > $null
                                    }
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [i] State: Learn") > $null
                                    }
                                    2
                                    {
                                        $analyzer.console_queue.Add(" [i] State: Listen") > $null
                                    }
                                    4
                                    {
                                        $analyzer.console_queue.Add(" [i] State: Speak") > $null
                                    }
                                    8
                                    {
                                        $analyzer.console_queue.Add(" [i] State: Standby") > $null
                                    }
                                    16
                                    {
                                        $analyzer.console_queue.Add(" [i] State: Active") > $null
                                    }
                                }

                                $analyzer.console_queue.Add(" [i] Priority: " + $hsrp_priority.ToString()) > $null
                                if ($hsrp_priority -lt 250)
                                {
                                    $analyzer.console_queue.Add(" [!] Priority May Be Low. Potential for Hijacking")
                                }
                                    
                                $analyzer.console_queue.Add(" [i] Group: " + $hsrp_group.ToString()) > $null
                                $analyzer.console_queue.Add(" [!] Password: " + $hsrp_auth) > $null
                                $analyzer.console_queue.Add(" [i] Group IP: " + $hsrp_groupip.ToString()) > $null
                            }
                            else
                            {
                                $analyzer.console_queue.Add("Packet received on HSRP UDP Port with wrong destination address") > $null
                            }
                        }
                    }
                    # mDNS Packet Inspection
                    5353
                    {
                        if ($analyzer.show_mdns)
                        {

                            # Need to gather full payload up front because of DNS compression
                            $payload_bytes = $binary_reader.ReadBytes(($UDP_length_uint - 2) * 4)

                            # mDNS destination should be 224.0.0.251
                            if ($destination_IP.ToString() -eq "224.0.0.251")
                            {
                                $analyzer.console_queue.Add("mDNS Packet Observed from " + $source_IP.ToString()) > $null
                                $mdns_queryid = DataToUInt16 $payload_bytes[0..1]
                                $mdns_control = $payload_bytes[2]
                                # split the control field so we can tell if this is query or response
                                $mdns_control_high = [Int]"0x$(('{0:X}' -f $mdns_control)[0])"
                                $mdns_control_low = [Int]"0x$(('{0:X}' -f $mdns_version_type)[1])"
                                $mdns_rcode = $payload_bytes[3]
                                $mdns_qdcount = DataToUInt16 $payload_bytes[4..5]
                                $mdns_ancount = DataToUInt16 $payload_bytes[6..7]
                                $mdns_nscount = DataToUInt16 $payload_bytes[8..9]
                                $mdns_arcount = DataToUInt16 $payload_bytes[10.11]

                                if ($mdns_control_high -lt 8)
                                {
                                    $analyzer.console_queue.Add(" [!] Potential for mDNS Cache Poisoning Attack") > $null
                                    $analyzer.console_queue.Add(" [i] Type: Query") > $null                
                                    $analyzer.console_queue.Add(" [i] Count: " + $mdns_qdcount.ToString()) > $null
                                    $payload_index = 12

                                    for ($i = 1; $i -le $mdns_qdcount; $i++)
                                    {
                                    
                                        $mdns_field_length = $payload_bytes[$payload_index]
                                        $payload_index = $payload_index + 1

                                        $name = ""

                                        while ($mdns_field_length -ne 0)
                                        {
                                            $mdns_field_value_bytes = $payload_bytes[$payload_index..($payload_index + $mdns_field_length - 1)]
                                            $payload_index = $payload_index + $mdns_field_length

                                            $mdns_field_value = DataToString 0 $mdns_field_length $mdns_field_value_bytes

                                            $name = $name + $mdns_field_value

                                            $mdns_field_length = $payload_bytes[$payload_index]
                                            $payload_index = $payload_index + 1

                                            # When DNS Compression is in use, the record will not be terminated with a null
                                            # Instead, a byte value of 192 (or C0) will be found indicating that the next byte
                                            # represents the offset into the DNS packet where the request/response continues.
                                            if ($mdns_field_length -eq 192)
                                            {
                                                $mdns_ptr_offset = $payload_bytes[$payload_index]
                                                $payload_index = $payload_index + 1

                                                $mdns_field_length = $payload_bytes[$mdns_ptr_offset]
                                                $mdns_ptr_offset = $mdns_ptr_offset + 1

                                                while ($mdns_field_length -ne 0)
                                                {
                                                    $mdns_field_value_bytes = $payload_bytes[$mdns_ptr_offset..($mdns_ptr_offset + $mdns_field_length - 1)]
                                                    $mdns_ptr_offset = $mdns_ptr_offset + $mdns_field_length

                                                    $mdns_field_value = DataToString 0 $mdns_field_length $mdns_field_value_bytes

                                                    $name = $name + $mdns_field_value

                                                    $mdns_field_length = $payload_bytes[$mdns_ptr_offset]
                                                    $mdns_ptr_offset = $mdns_ptr_offset + 1 
                                                    
                                                    if ($mdns_field_length -ne 0)
                                                    {
                                                        $name = ($name + ".")
                                                    }  
                                                }
                                                break
                                            }

                                            if ($mdns_field_length -ne 0)
                                            {
                                                $name = ($name + ".")
                                            }
                                        }

                                        $mdns_record_type = $payload_bytes[$payload_index..($payload_index + 1)]
                                        $payload_index = $payload_index + 2

                                        $mdns_record_class = $payload_bytes[$payload_index..($payload_index + 1)]
                                        $payload_index = $payload_index + 2
                                    
                                        $analyzer.console_queue.Add(" [i] Host: " + $name) > $null
                                    }
                                }
                                else
                                {
                                    $analyzer.console_queue.Add(" [i] Type: Response") > $null
                                    $analyzer.console_queue.Add(" [i] Count: " + $mdns_ancount.ToString()) > $null
                                    # May Parse mDNS Responses Further In The Future
                                }
                            }
                            else
                            {
                                $analyzer.console_queue.Add("Packet received on mDNS UDP Port with wrong destination address") > $null
                            }
                        }
                    }
                    # LLMNR Packet Inspection
                    5355
                    {
                        if ($analyzer.show_llmnr)
                        {
                            if ($destination_IP.ToString() -eq "224.0.0.252")
                            {
                                $analyzer.console_queue.Add("LLMNR Packet Observed from " + $source_IP.ToString()) > $null
                                $llmnr_queryid = DataToUInt16 $payload_bytes[0..1]
                                llmnr_control = $payload_bytes[2]
                                # split the control field so we can tell if this is query or response
                                $llmnr_control_high = [Int]"0x$(('{0:X}' -f $llmnr_control)[0])"
                                $llmnr_control_low = [Int]"0x$(('{0:X}' -f $llmnr_version_type)[1])"
                                $llmnr_rcode = $payload_bytes[3]
                                $llmnr_qdcount = DataToUInt16 $payload_bytes[4..5]
                                $llmnr_ancount = DataToUInt16 $payload_bytes[6..7]
                                $llmnr_nscount = DataToUInt16 $payload_bytes[8..9]
                                $llmnr_arcount = DataToUInt16 $payload_bytes[10.11]

                                if ($llmnr_control_high -lt 8)
                                {
                                    $analyzer.console_queue.Add(" [!] Potential for LLMNR Cache Poisoning Attack") > $null
                                    $analyzer.console_queue.Add(" [i] Type: Query") > $null                
                                    $analyzer.console_queue.Add(" [i] Count: " + $llmnr_qdcount.ToString()) > $null
                                    $payload_index = 12

                                    for ($i = 1; $i -le $llmnr_qdcount; $i++)
                                    {
                                    
                                        $llmnr_field_length = $payload_bytes[$payload_index]
                                        $payload_index = $payload_index + 1

                                        $name = ""

                                        while ($llmnr_field_length -ne 0)
                                        {
                                            $llmnr_field_value_bytes = $payload_bytes[$payload_index..($payload_index + $llmnr_field_length - 1)]
                                            $payload_index = $payload_index + $llmnr_field_length

                                            $llmrn_field_value = DataToString 0 $mdns_field_length $llmnr_field_value_bytes

                                            $name = $name + $llmnr_field_value

                                            $llmnr_field_length = $payload_bytes[$payload_index]
                                            $payload_index = $payload_index + 1

                                            # When DNS Compression is in use, the record will not be terminated with a null
                                            # Instead, a byte value of 192 (or C0) will be found indicating that the next byte
                                            # represents the offset into the DNS packet where the request/response continues.
                                            if ($llmnr_field_length -eq 192)
                                            {
                                                $llmnr_ptr_offset = $payload_bytes[$payload_index]
                                                $payload_index = $payload_index + 1

                                                $llmnr_field_length = $payload_bytes[$llmnr_ptr_offset]
                                                $llmnr_ptr_offset = $mdns_ptr_offset + 1

                                                while ($llmnr_field_length -ne 0)
                                                {
                                                    $llmnr_field_value_bytes = $payload_bytes[$llmnr_ptr_offset..($llmnr_ptr_offset + $llmnr_field_length - 1)]
                                                    $llmnr_ptr_offset = $llmnr_ptr_offset + $llmnr_field_length

                                                    $llmnr_field_value = DataToString 0 $llmnr_field_length $llmnr_field_value_bytes

                                                    $name = $name + $llmnr_field_value

                                                    $llmnr_field_length = $payload_bytes[$llmnr_ptr_offset]
                                                    $llmnr_ptr_offset = $llmnr_ptr_offset + 1 
                                                    
                                                    if ($llmnr_field_length -ne 0)
                                                    {
                                                        $name = ($name + ".")
                                                    }  
                                                }
                                                break
                                            }

                                            if ($llmnr_field_length -ne 0)
                                            {
                                                $name = ($name + ".")
                                            }
                                        }

                                        $llmnr_record_type = $payload_bytes[$payload_index..($payload_index + 1)]
                                        $payload_index = $payload_index + 2

                                        $llmnr_record_class = $payload_bytes[$payload_index..($payload_index + 1)]
                                        $payload_index = $payload_index + 2
                                    
                                        $analyzer.console_queue.Add(" [i] Host: " + $name) > $null
                                    }
                                }
                                else
                                {
                                    $analyzer.console_queue.Add(" [i] Type: Response") > $null
                                    $analyzer.console_queue.Add(" [i] Count: " + $llmnr_ancount.ToString()) > $null
                                    # May Parse LLMNR Responses Further In The Future
                                }
                            }
                            else
                            {
                                $analyzer.console_queue.Add("Packet received on LLMNR UDP Port with wrong destination address") > $null
                            }
                        }
                    }
                    default
                    {
                        # Do Nothing
                    }
                }

            }
            # OSPF Processing
            89
            {
                if ($analyzer.show_ospf)
                {
                    if ($destination_IP.ToString() -eq "224.0.0.5")
                    {
                        $ospf_version = $binary_reader.ReadByte()
                        $ospf_type = $binary_reader.ReadByte()
                        $ospf_length = DataToUInt16 $binary_reader.ReadBytes(2)
                        $ospf_router_bytes = $binary_reader.ReadBytes(4)
                        $ospf_router = [System.Net.IPAddress]$ospf_router_bytes
                        $ospf_area_bytes = $binary_reader.ReadBytes(4)
                        $ospf_area = [System.Net.IPAddress]$ospf_area_bytes
                        $ospf_checksum = DataToUInt16 $binary_reader.ReadBytes(2)
                        $ospf_authType = DataToUInt16 $binary_reader.ReadBytes(2)

                        $analyzer.console_queue.Add("OSPF v" + $ospf_version.ToString() + " Packet Observed from " + $source_IP.ToString()) > $null


                        switch($ospf_authType)
                        {
                            # Handle OSPF Packets with NULL Auth
                            0
                            {
                                switch($ospf_type)
                                {
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: Hello packet.") > $null
                                    }
                                    2
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: DB Descriptor packet.") > $null
                                    }
                                    3
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: LS Request packet.") > $null
                                    }
                                    4
                                    {
                                        $analyzer.console_queue.Add(" [!] Type: LS Update packet.") > $null                    
                                    }
                                    5
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: LS Ack packet.") > $null
                                    }
                                }

                                $analyzer.console_queue.Add(" [!] Auth: NULL") > $null
                            }
                            # Handle OSPF Packets with Password Auth
                            1
                            {
                                switch($ospf_type)
                                {
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: Hello packet.") > $null
                                    }
                                    2
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: DB Descriptor packet.") > $null
                                    }
                                    3
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: LS Request packet.") > $null
                                    }
                                    4
                                    {
                                        $analyzer.console_queue.Add(" [!] Type: LS Update packet.") > $null                    
                                    }
                                    5
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: LS Ack packet.") > $null
                                    }
                                }

                                $analyzer.console_queue.Add(" [!] Auth: Password") > $null
                                $password_bytes = $binary_reader.ReadBytes(8)
                                $ospf_authData = DataToString 0 8 $password_bytes
                                $analyzer.console_queue.Add(" [!] Password: " + $ospf_authData) > $null
                            }
                            # Handle OSPF Packets With Cryptographic Auth
                            2
                            {
                                $null_bytes = $binary_reader.ReadBytes(2)
                                $ospf_key_id = $binary_reader.ReadByte()
                                $ospf_auth_length = $binary_reader.ReadByte()
                                $ospf_auth_sequence_bytes = $binary_reader.ReadBytes(4)
                                $ospf_auth_sequence = DataToUInt32 $ospf_auth_sequence_bytes
                                    
                                switch($ospf_type)
                                {
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: Hello packet.") > $null
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
                                        $ospf_netmask_bytes = $binary_reader.ReadBytes(4)
                                        $ospf_netmask = [System.Net.IPAddress]$ospf_netmask_bytes
                                        $opsf_hello_interval = DataToUInt16 $binary_reader.ReadBytes(2)
                                        $ospf_hello_options = $binary_reader.ReadByte()
                                        $ospf_hello_router_pri = $binary_reader.ReadByte()
                                        $ospf_dead_interval_bytes = $binary_reader.ReadBytes(4)
                                        $ospf_dead_interval = DataToUInt32 $ospf_dead_interval_bytes
                                        $ospf_dr_bytes = $binary_reader.ReadBytes(4)
                                        $ospf_dr_ip = [System.Net.IPAddress]$ospf_dr_bytes
                                        $ospf_br_bytes = $binary_reader.ReadBytes(4)
                                        $ospf_br_ip = [System.Net.IPAddress]$ospf_br_bytes
                                        $ospf_crypt_hash_bytes = $binary_reader.ReadBytes(16)
                                        $ospf_crypt_hash = DataToHexString 0 16 $ospf_crypt_hash_bytes
                                        $analyzer.console_queue.Add(" [i] Auth Hash: " + $ospf_crypt_hash.ToString())
                                        $analyzer.console_queue.Add(" [i] Designated Router: " + $ospf_dr_ip.ToString())
                                    }
                                    2
                                    {
                                        # May need to expand on DB Descriptor Packets (Just to get routing table).
                                        $analyzer.console_queue.Add(" [i] Type: DB Descriptor packet.") > $null
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
                                            
                                    }
                                    3
                                    {
                                        # Link-State Request Packets are Less Interesting
                                        $analyzer.console_queue.Add(" [i] Type: LS Request packet.") > $null
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null

                                    }
                                    4
                                    {
                                        # Link-State Update Packets Can Be Used to Build a Routing Table
                                        $analyzer.console_queue.Add(" [!] Type: LS Update packet.") > $null                    
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null

                                    }
                                    5
                                    {
                                        # Link-State Acknowledgement Packets May Need to be Used to Validate Updates
                                        $analyzer.console_queue.Add(" [i] Type: LS Ack packet.") > $null
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null

                                    }
                                }
                            }
                        }
 
                    }
                    elseif ($destination_IP.ToString() -eq "224.0.0.6")
                    {
                        $ospf_version = $binary_reader.ReadByte()
                        $ospf_type = $binary_reader.ReadByte()
                        $ospf_length = DataToUInt16 $binary_reader.ReadBytes(2)
                        $ospf_router_bytes = $binary_reader.ReadBytes(4)
                        $ospf_router = [System.Net.IPAddress]$ospf_router_bytes
                        $ospf_area_bytes = $binary_reader.ReadBytes(4)
                        $ospf_area = [System.Net.IPAddress]$ospf_area_bytes
                        $ospf_checksum = DataToUInt16 $binary_reader.ReadBytes(2)
                        $ospf_authType = DataToUInt16 $binary_reader.ReadBytes(2)
                            
                        $analyzer.console_queue.Add("OSPF v" + $ospf_version.ToString() + " Packet Observed from " + $source_IP.ToString()) > $null


                        switch($ospf_authType)
                        {
                            # Handle OSPF Packets with NULL Auth
                            0
                            {
                                switch($ospf_type)
                                {
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: Hello packet.") > $null
                                    }
                                    2
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: DB Descriptor packet.") > $null
                                    }
                                    3
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: LS Request packet.") > $null
                                    }
                                    4
                                    {
                                        $analyzer.console_queue.Add(" [!] Type: LS Update packet.") > $null                    
                                    }
                                    5
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: LS Ack packet.") > $null
                                    }
                                }
                                    
                                $analyzer.console_queue.Add(" [!] Auth: NULL") > $null
                            }
                            # Handle OSPF Packets with Password Auth
                            1
                            {
                                switch($ospf_type)
                                {
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: Hello packet.") > $null
                                    }
                                    2
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: DB Descriptor packet.") > $null
                                    }
                                    3
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: LS Request packet.") > $null
                                    }
                                    4
                                    {
                                        $analyzer.console_queue.Add(" [!] Type: LS Update packet.") > $null                    
                                    }
                                    5
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: LS Ack packet.") > $null
                                    }
                                }

                            $analyzer.console_queue.Add(" [!] Auth: Password") > $null
                            $password_bytes = $binary_reader.ReadBytes(8)
                            $ospf_authData = DataToString 0 8 $password_bytes
                            $analyzer.console_queue.Add(" [!] Password: " + $ospf_authData) > $null
                        }
                            # Handle OSPF Packets With Cryptographic Auth
                            2
                            {
                                $null_bytes = $binary_reader.ReadBytes(2)
                                $ospf_key_id = $binary_reader.ReadByte()
                                $ospf_auth_length = $binary_reader.ReadByte()
                                $ospf_auth_sequence_bytes = $binary_reader.ReadBytes(4)
                                $ospf_auth_sequence = DataToUInt32 $ospf_auth_sequence_bytes

                                switch($ospf_type)
                                {
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [i] Type: Hello packet.") > $null
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
                                        $ospf_netmask_bytes = $binary_reader.ReadBytes(4)
                                        $ospf_netmask = [System.Net.IPAddress]$ospf_netmask_bytes
                                        $opsf_hello_interval = DataToUInt16 $binary_reader.ReadBytes(2)
                                        $ospf_hello_options = $binary_reader.ReadByte()
                                        $ospf_hello_router_pri = $binary_reader.ReadByte()
                                        $ospf_dead_interval_bytes = $binary_reader.ReadBytes(4)
                                        $ospf_dead_interval = DataToUInt32 $ospf_dead_interval_bytes
                                        $ospf_dr_bytes = $binary_reader.ReadBytes(4)
                                        $ospf_dr_ip = [System.Net.IPAddress]$ospf_dr_bytes
                                        $ospf_br_bytes = $binary_reader.ReadBytes(4)
                                        $ospf_br_ip = [System.Net.IPAddress]$ospf_br_bytes
                                        $ospf_crypt_hash_bytes = $binary_reader.ReadBytes(16)
                                        $ospf_crypt_hash = DataToHexString 0 16 $ospf_crypt_hash_bytes
                                        $analyzer.console_queue.Add(" [i] Auth Hash: " + $ospf_crypt_hash.ToString())
                                        $analyzer.console_queue.Add(" [i] Designated Router: " + $ospf_dr_ip.ToString())
                                    }
                                    2
                                    {
                                        # May need to expand on DB Descriptor Packets (Just to get routing table).
                                        $analyzer.console_queue.Add(" [i] Type: DB Descriptor packet.") > $null
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null

                                    }
                                    3
                                    {
                                        # Link-State Request Packets are Less Interesting
                                        $analyzer.console_queue.Add(" [i] Type: LS Request packet.") > $null
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null

                                    }
                                    4
                                    {
                                        # Link-State Update Packets Can Be Used to Build a Routing Table
                                        $analyzer.console_queue.Add(" [!] Type: LS Update packet.") > $null                    
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null

                                    }
                                    5
                                    {
                                        # Link-State Acknowledgement Packets May Need to be Used to Validate Updates
                                        $analyzer.console_queue.Add(" [i] Type: LS Ack packet.") > $null
                                        $analyzer.console_queue.Add(" [i] Auth: Cryptographic (MD5)") > $null
                                        $analyzer.console_queue.Add(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
                                        $analyzer.console_queue.Add(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null

                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        $analyzer.console_queue.Add("Packet received for OSPF Protocol ID with wrong destination address") > $null
                    }
                }
                
            }
            # VRRP Processing
            112
            {
                if ($analyzer.show_vrrp)
                {
                    if ($destination_IP.ToString() -eq "224.0.0.18")
                    {
                        $vrrp_version_type = $binary_reader.ReadByte()
                        $vrrp_version = [Int]"0x$(('{0:X}' -f $vrrp_version_type)[0])"
                        # Only type 1 is defined in the RFC, all others are non-existent
                        $vrrp_type = [Int]"0x$(('{0:X}' -f $vrrp_version_type)[1])"
                        $vrrp_rtr_id = $binary_reader.ReadByte()
                        $vrrp_priority = $binary_reader.ReadByte()
                        $vrrp_addr_count = $binary_reader.ReadByte()
                    
                        $analyzer.console_queue.Add("VRRP v" + $vrrp_version + " Packet Observed from " + $source_IP.ToString()) > $null
                        $analyzer.console_queue.Add(" [i] Router ID: " + $vrrp_rtr_id.ToString())
                        $analyzer.console_queue.Add(" [i] Priority: " + $vrrp_priority.ToString())
                        if ($vrrp_priority -lt 250)
                        {
                            $analyzer.console_queue.Add(" [!] Priority May Be Low. Potential for Hijacking")
                        }
                    
                        $analyzer.console_queue.Add(" [i] Addresses: " + $vrrp_addr_count.ToString())
                            
                        # VRRP v2 is IPv4 Only
                        if ($vrrp_version -lt 3)
                        {
                            $vrrp_auth_type = $binary_reader.ReadByte()
                            $vrrp_advert_interval = $binary_reader.ReadByte()
                            $vrrp_checksum = DataToUInt16 $binary_reader.ReadBytes(2)

                            # Might be wise to validate this against packet length to handle malformed packets
                            for ($i = 1; $i -le $vrrp_addr_count; $i++)
                            {
                                try
                                {
                                    $vrrp_address_bytes = $binary_reader.ReadBytes(4)
                                    $vrrp_address = [System.Net.IPAddress]$vrrp_address_bytes

                                    $analyzer.console_queue.Add(" [i] Address " + $i.ToString() + ": " + $vrrp_address.ToString()) > $null
                                }
                                catch
                                {
                                    $analyzer.console_queue.Add(" [w] Malformed Packet!!")
                                }
                            }

                            try
                            {
                                switch ($vrrp_auth_type)
                                {
                                    0
                                    {
                                        $analyzer.console_queue.Add(" [!] Auth: None") > $null
                                    }
                                    1
                                    {
                                        $analyzer.console_queue.Add(" [!] Auth: Simple Text Password") > $null
                                        $vrrp_auth_data_bytes = $binary_reader.ReadBytes(8)
                                        $vrrp_auth_data = DataToString 0 8 $vrrp_auth_data_bytes
                                        $analyzer.console_queue.Add(" [!] Password: " + $vrrp_auth_data) > $null
                                    }
                                    2
                                    {
                                        $analyzer.console_queue.Add(" [i] Auth: IP Auth Header") > $null
                                    }    
                                }   
                            }
                            catch
                            {
                            }
                        }
                        elseif ($IP_version -eq 4)
                        {
                            $vrrp_rsv_advert_interval_bytes = $binary_reader.ReadBytes(4)
                            $vrrp_rsv_advert_interval = DataToUInt32 $vrrp_rsv_advert_interval_bytes
                            $vrrp_checksum = DataToUInt16 $binary_reader.ReadBytes(2)
                                
                            # Might be wise to validate this against packet length to handle malformed packets
                            for ($i = 1; $i -le $vrrp_addr_count; $i++)
                            {
                                try
                                {
                                    $vrrp_address_bytes = $binary_reader.ReadBytes(4)
                                    $vrrp_address = [System.Net.IPAddress]$vrrp_address_bytes
                                        
                                    $analyzer.console_queue.Add(" [i] Address " + $i.ToString() + ": " + $vrrp_address.ToString()) > $null
                                }
                                catch
                                {
                                $analyzer.console_queue.Add(" [w] Malformed Packet!!")
                                }
                            }
                        }
                        elseif ($IP_version -eq 6)
                        {
                            $vrrp_rsv_advert_interval_bytes = $binary_reader.ReadBytes(4)
                            $vrrp_rsv_advert_interval = DataToUInt32 $vrrp_rsv_advert_interval_bytes
                            $vrrp_checksum = DataToUInt16 $binary_reader.ReadBytes(2)
                                
                            # Might be wise to validate this against packet length to handle malformed packets
                            for ($i = 1; $i -le $vrrp_addr_count; $i++)
                            {
                                try
                                {
                                    $vrrp_address_bytes = $binary_reader.ReadBytes(16)
                                    $vrrp_address = [System.Net.IPAddress]$vrrp_address_bytes
                                        
                                    $analyzer.console_queue.Add(" [i] Address " + $i.ToString() + ": " + $vrrp_address.ToString()) > $null
                                }
                                catch
                                {
                                    $analyzer.console_queue.Add(" [w] Malformed Packet!!")
                                }
                            }
                        }                    
                    }
                    else
                    {
                        $analyzer.console_queue.Add("Packet received on VRRP Protocol ID with wrong destination address") > $null
                    }               
                }
            }
        }
    }

    $binary_reader.Close()
    $memory_stream.Dispose()
    $memory_stream.Close()
}

# Moved sniffer to main script instead of function so thread can be properly shut down
$analyzer.console_queue.Add("Starting sniffer...") > $null
$sniffer_runspace = [RunspaceFactory]::CreateRunspace()
$sniffer_runspace.Open()
$sniffer_runspace.SessionStateProxy.SetVariable('analyzer',$analyzer)
$sniffer_powershell = [PowerShell]::Create()
$sniffer_powershell.Runspace = $sniffer_runspace
$sniffer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
$sniffer_powershell.AddScript($sniffer_scriptblock).AddArgument($IP).AddArgument($RunTime) > $null
$sniffer_powershell.BeginInvoke() > $null
    
    while ($analyzer.running -or ($analyzer.console_queue.Count -gt 0))
    {

        while($analyzer.console_queue.Count -gt 0)
        {
                switch -wildcard ($analyzer.console_queue[0])
                {
                    "*[!]*"
                    {
                        Write-Host $analyzer.console_queue[0] -ForegroundColor "DarkYellow"
                        $analyzer.console_queue.RemoveAt(0)                        
                    }
                    "Windows Firewall = Enabled"
                    {
                        Write-Warning($analyzer.console_queue[0])
                        $analyzer.console_queue.RemoveAt(0)
                    }

                    default
                    {
                        Write-Output $analyzer.console_queue[0]
                        $analyzer.console_queue.RemoveAt(0)
                    }

                } 
        }

        if([Console]::KeyAvailable)
        {
            $key = [System.Console]::ReadKey()

            switch ($key.KeyChar)
            {
                'h'
                {
                    $analyzer.show_hsrp = !$analyzer.show_hsrp
                    if ($analyzer.show_hsrp)
                    {
                        $analyzer.console_queue.Add("HSRP Toggle: ON") > $null
                    }
                    else
                    {
                        $analyzer.console_queue.Add("HSRP Toggle: OFF") > $null
                    }
                }
                'd'
                {
                    $analyzer.show_dhcp = !$analyzer.show_dhcp
                    if ($analyzer.show_dhcp)
                    {
                        $analyzer.console_queue.Add("DHCP Toggle: ON") > $null
                    }
                    else
                    {
                        $analyzer.console_queue.Add("DHCP Toggle: OFF") > $null
                    }
                }
                'o'
                {
                    $analyzer.show_ospf = !$analyzer.show_ospf
                    if ($analyzer.show_ospf)
                    {
                        $analyzer.console_queue.Add("OSPF Toggle: ON") > $null
                    }
                    else
                    {
                        $analyzer.console_queue.Add("OSPF Toggle: OFF") > $null
                    }

                }
                'v'
                {
                    $analyzer.show_vrrp = !$analyzer.show_vrrp
                    if ($analyzer.show_vrrp)
                    {
                        $analyzer.console_queue.Add("VRRP Toggle: ON") > $null
                    }
                    else
                    {
                        $analyzer.console_queue.Add("VRRP Toggle: OFF") > $null
                    }
                }
                'l'
                {
                    $analyzer.show_llmnr = !$analyzer.show_llmnr
                    if ($analyzer.show_llmnr)
                    {
                        $analyzer.console_queue.Add("LLMNR Toggle: ON") > $null
                    }
                    else
                    {
                        $analyzer.console_queue.Add("LLMNR Toggle: OFF") > $null
                    }

                }
                'm'
                {
                    $analyzer.show_mdns = !$analyzer.show_mdns
                    if ($analyzer.show_mdns)
                    {
                        $analyzer.console_queue.Add("mDNS Toggle: ON") > $null
                    }
                    else
                    {
                        $analyzer.console_queue.Add("mDNS Toggle: OFF") > $null
                    }

                }
                'n'
                {
                    $analyzer.show_nbns = !$analyzer.show_nbns
                    if ($analyzer.show_nbns)
                    {
                        $analyzer.console_queue.Add("NBNS Toggle: ON") > $null
                    }
                    else
                    {
                        $analyzer.console_queue.Add("NBNS Toggle: OFF") > $null
                    }
                }
                'q'
                {
                    Write-Host ("Shuting Down Analyzer...Please Wait") > $null

                    # Delete Multicast Firewall Rule
                    if ($admin)
                    {
                        $rule = "cmd.exe /C netsh advfirewall firewall delet rule name=`"Multicast Inbound Allow`""
                        Invoke-Expression $rule > $null
                    }

                    # Set analyzer to stopped and reset show variables
                    $analyzer.running = $false
                    $analyzer.show_dhcp = $true
                    $analyzer.show_hsrp = $true
                    $analyzer.show_llmnr = $true
                    $analyzer.show_mdns = $true
                    $analyzer.show_nbns = $true
                    $analyzer.show_ospf = $true
                    $analyzer.show_vrrp = $true

                    # Kill the sniffer objects
                    $sniffer_powershell.Dispose()
                    $sniffer_runspace.CloseAsync()
                    $sniffer_runspace.Dispose()
                    Write-Host ("Shutdown Complete") > $null
                    return
                }
                default
                {
                    $analyzer.console_queue.Add("Runtime Interactive Help:") > $null
                    $analyzer.console_queue.Add("D = DHCP Toggle") > $null
                    $analyzer.console_queue.Add("H = HSRP Toggle") > $null
                    $analyzer.console_queue.Add("L = LLMNR Toggle") > $null
                    $analyzer.console_queue.Add("M = mDNS Toggle") > $null
                    $analyzer.console_queue.Add("O = OSPF Toggle") > $null
                    $analyzer.console_queue.Add("V = VRRP Toggle") > $null
                    $analyzer.console_queue.Add("Q = Shut Down Analyzer") > $null
                }
            }
        }

        Start-Sleep -m 5
    }
}
